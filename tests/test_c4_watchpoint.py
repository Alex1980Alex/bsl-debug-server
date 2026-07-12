"""C4 (roadmap 260708 §8.4) unit tests: watchpoint / data BP emulation.

Covers the pure comparator/predicate helpers, assignment-line planning,
read_timeline key/skip filtering, and the deferred compare/decide flow (record
vs change vs halt-promotion) against a mock client.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import autonomy
import watchpoints


# --- match_predicate ------------------------------------------------------
class TestMatchPredicate:
    def test_numeric(self):
        assert watchpoints.match_predicate("0", "=", "0")
        assert watchpoints.match_predicate("0", "<", "5")
        assert watchpoints.match_predicate("10", ">", "5")
        assert watchpoints.match_predicate("5", "<=", "5")
        assert watchpoints.match_predicate("5", ">=", "5")
        assert not watchpoints.match_predicate("5", "<", "5")

    def test_decimal_comma(self):
        assert watchpoints.match_predicate("3,14", ">", "3")

    def test_boolean(self):
        assert watchpoints.match_predicate("Истина", "=", "True")
        assert watchpoints.match_predicate("Ложь", "<>", "Истина")

    def test_string_equality(self):
        assert watchpoints.match_predicate("hold-c1b", "=", "hold-c1b")
        assert watchpoints.match_predicate("abc", "<>", "abd")

    def test_unknown_op_false(self):
        assert not watchpoints.match_predicate("1", "~=", "1")


# --- parse_break_when -----------------------------------------------------
class TestParseBreakWhen:
    def test_ops(self):
        assert watchpoints.parse_break_when("= 0") == ("=", "0")
        assert watchpoints.parse_break_when("<> Истина") == ("<>", "Истина")
        assert watchpoints.parse_break_when("<= 100") == ("<=", "100")
        assert watchpoints.parse_break_when(">=5") == (">=", "5")

    def test_leading_name_ignored(self):
        assert watchpoints.parse_break_when("Итог = 0") == ("=", "0")

    def test_empty(self):
        assert watchpoints.parse_break_when("") is None
        assert watchpoints.parse_break_when("   ") is None
        assert watchpoints.parse_break_when("= ") is None


# --- plan_watchpoints -----------------------------------------------------
class TestPlanWatchpoints:
    def test_assignment_lines(self):
        src = [
            "Процедура Тест()",
            "    Ответ = 1;",
            "    Если Ответ = 5 Тогда",  # comparison — NOT an assignment
            "        Ответ = 2;",
            "    КонецЕсли;",
            "КонецПроцедуры",
        ]
        rng = autonomy.find_method_range(src, "Тест")
        plan = watchpoints.plan_watchpoints(src, "Ответ", autonomy.find_assignment_lines, rng)
        lines = [p["line"] for p in plan]
        assert lines == [2, 4]


# --- read_timeline --------------------------------------------------------
class TestReadTimeline:
    def _seed(self, tmp_path, rows):
        (tmp_path / "sess.watch.jsonl").write_text(
            "\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n", encoding="utf-8"
        )

    def test_filter_and_skip(self, tmp_path):
        rows = [
            {"object_id": "o", "property_id": "p", "line": 2, "new": "pre"},  # pre-arm, skipped
            {"object_id": "o", "property_id": "p", "line": 2, "new": "1"},
            {"object_id": "z", "property_id": "p", "line": 9, "new": "x"},  # not in keys
        ]
        self._seed(tmp_path, rows)
        out = watchpoints.read_timeline(tmp_path, "sess", "r1", {("o", "p", 2)}, skip_lines=1)
        assert len(out) == 1 and out[0]["new"] == "1"

    def test_missing_file(self, tmp_path):
        assert watchpoints.read_timeline(tmp_path, "nope", "r", {("o", "p", 2)}, 0) == []

    def test_run_id_filter(self, tmp_path):
        # review 260712: a prior run's late write (run_id=r0) sharing a key must
        # NOT leak into a re-armed run (run_id=r1). Records with no run_id (legacy)
        # are still included.
        rows = [
            {"object_id": "o", "property_id": "p", "line": 2, "new": "old-run", "run_id": "r0"},
            {"object_id": "o", "property_id": "p", "line": 2, "new": "cur", "run_id": "r1"},
            {"object_id": "o", "property_id": "p", "line": 2, "new": "legacy"},  # no run_id
        ]
        self._seed(tmp_path, rows)
        out = watchpoints.read_timeline(tmp_path, "sess", "r1", {("o", "p", 2)}, skip_lines=0)
        news = [e["new"] for e in out]
        assert "old-run" not in news
        assert "cur" in news and "legacy" in news


# --- fire / compare flow --------------------------------------------------
class _MockClient:
    def __init__(self, eval_value, tmp_path, mode="record_only", predicate=None):
        self.session_id = "sess"
        self._log_dir = tmp_path
        self._watch_last = {}
        self._watch_changes = []
        self._user_visible_stops = set()
        self._signalled = 0
        key = ("o", "p", 2)
        self._watchpoints = {
            key: {"name": "Ответ", "mode": mode, "predicate": predicate, "run_id": "r1",
                  "fires": 0, "max_fires": 200}
        }
        self._eval_value = eval_value
        self.step = AsyncMock()

    async def eval_expression(self, expression, target_uuid, stack_level=0):
        # logpoints._scalar passes non-dict through unchanged.
        return self._eval_value

    def _signal_bp_stop(self):
        self._signalled += 1


def _stack():
    return [{"moduleID": {"objectID": "o", "propertyID": "p"}, "lineNo": 2}]


@pytest.mark.asyncio
async def test_record_only_continues(tmp_path):
    c = _MockClient("1", tmp_path, mode="record_only")
    fired = await watchpoints.fire_watchpoint(c, "t1", _stack(), tmp_path)
    assert fired is True
    await watchpoints.drain_active()
    c.step.assert_awaited_once()  # always Continue
    assert c._signalled == 0
    assert len(c._watch_changes) == 1
    assert c._watch_changes[0]["old"] is None and c._watch_changes[0]["changed"] is True


@pytest.mark.asyncio
async def test_unchanged_not_recorded(tmp_path):
    c = _MockClient("1", tmp_path, mode="record_only")
    c._watch_last[("t1", "Ответ")] = "1"  # already seen == "1"
    await watchpoints.fire_watchpoint(c, "t1", _stack(), tmp_path)
    await watchpoints.drain_active()
    c.step.assert_awaited_once()  # Continue
    assert c._watch_changes == []  # unchanged → no record


@pytest.mark.asyncio
async def test_break_on_first_change_halts(tmp_path):
    c = _MockClient("2", tmp_path, mode="break_on_first_change")
    c._watch_last[("t1", "Ответ")] = "1"  # prior value → change to "2"
    await watchpoints.fire_watchpoint(c, "t1", _stack(), tmp_path)
    await watchpoints.drain_active()
    c.step.assert_not_awaited()  # left halted
    assert c._signalled == 1
    assert "t1" in c._user_visible_stops
    assert c._watchpoints[("o", "p", 2)]["halted_at"]["new"] == "2"


@pytest.mark.asyncio
async def test_break_when_predicate(tmp_path):
    c = _MockClient("0", tmp_path, mode="break_when", predicate=("=", "0"))
    c._watch_last[("t1", "Ответ")] = "5"  # change 5 → 0, predicate "= 0" satisfied
    await watchpoints.fire_watchpoint(c, "t1", _stack(), tmp_path)
    await watchpoints.drain_active()
    c.step.assert_not_awaited()  # halted on predicate match
    assert "t1" in c._user_visible_stops


@pytest.mark.asyncio
async def test_break_when_predicate_unsatisfied_continues(tmp_path):
    c = _MockClient("3", tmp_path, mode="break_when", predicate=("=", "0"))
    c._watch_last[("t1", "Ответ")] = "5"  # change 5 → 3, predicate "= 0" NOT satisfied
    await watchpoints.fire_watchpoint(c, "t1", _stack(), tmp_path)
    await watchpoints.drain_active()
    c.step.assert_awaited_once()  # Continue — predicate not met
    assert c._signalled == 0


@pytest.mark.asyncio
async def test_fire_cap(tmp_path):
    c = _MockClient("1", tmp_path, mode="record_only")
    c._watchpoints[("o", "p", 2)]["max_fires"] = 1
    c._watchpoints[("o", "p", 2)]["fires"] = 1  # already at cap → next is capped
    await watchpoints.fire_watchpoint(c, "t1", _stack(), tmp_path)
    await watchpoints.drain_active()
    c.step.assert_awaited_once()  # still Continue (never freeze)
    assert c._watchpoints[("o", "p", 2)]["capped"] is True
    assert c._watch_changes == []  # capped → no eval/record


@pytest.mark.asyncio
async def test_no_match_returns_false(tmp_path):
    c = _MockClient("1", tmp_path)
    other = [{"moduleID": {"objectID": "x", "propertyID": "y"}, "lineNo": 99}]
    assert await watchpoints.fire_watchpoint(c, "t1", other, tmp_path) is False
