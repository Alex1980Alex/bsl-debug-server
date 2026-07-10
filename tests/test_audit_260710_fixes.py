"""Regression tests for the 260710 audit fixes (roadmap 260708).

Each test pins a specific defect from
docs/roadmap/260710_AUDIT_260708_AUTONOMOUS_1C_DEBUGGING.md so it cannot recur.
IDs (H-1/H-2/... M-1/...) match the audit report.
"""

from __future__ import annotations

import asyncio
import base64
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import autonomy
import exception_bps
import logpoints
from mcp_debug_server import RDBGClient, _await_bp_stop

UUID = "11111111-2222-3333-4444-555555555555"


def _client() -> RDBGClient:
    c = RDBGClient(debug_url="http://localhost:1550", infobase_alias="TestDB")
    c._post = AsyncMock(return_value=ET.Element("empty"))
    return c


def _frame(oid, pid, line, pres=""):
    return {"moduleID": {"objectID": oid, "propertyID": pid}, "lineNo": line, "presentation": pres}


class _FakeTask:
    def __init__(self):
        self.cancelled_ = False

    def done(self):
        return False

    def cancel(self):
        self.cancelled_ = True


# H-3 — exception_module filter matches ANY frame (not outermost) -------------
class TestH3ExceptionModuleAnyFrame:
    def test_matches_inner_fault_frame_not_only_outermost(self):
        # RDBG stack is OUTERMOST-first: entry-point first, throwing module LAST.
        stack = [_frame("o", "p", 1, "ВнешнийМодуль.Точка"), _frame("o2", "p2", 9, "МойМодуль.Кидает")]
        filters = [{"message_pattern": "", "module_pattern": "МойМодуль"}]
        assert exception_bps.should_halt(filters, {"info": "boom"}, stack) is True

    def test_no_match_returns_false(self):
        stack = [_frame("o", "p", 1, "ЧужойМодуль")]
        filters = [{"message_pattern": "", "module_pattern": "МойМодуль"}]
        assert exception_bps.should_halt(filters, {"info": "boom"}, stack) is False


# H-1 — UI+ escalation must not self-cancel the ping task ---------------------
@pytest.mark.asyncio
class TestH1SelfCancelGuard:
    def _wire(self, c):
        c.attach = AsyncMock()
        c.init_settings = AsyncMock()
        c.clear_break_on_next_statement = AsyncMock()
        c.set_auto_attach_settings = AsyncMock()
        c._registered = True
        calls = []
        c.detach = AsyncMock(side_effect=lambda cancel_ping=True: calls.append(cancel_ping) or True)
        return calls

    async def test_escalation_from_ping_task_does_not_cancel_it(self):
        c = _client()
        calls = self._wire(c)

        async def run():
            c._ping_task = asyncio.current_task()  # WE are the ping task
            await c._ui_plus_full_reattach_and_retry("pingDebugUIParams", "<b/>", True)

        task = asyncio.create_task(run())
        await task
        assert calls == [False]  # detach(cancel_ping=False): don't kill our own loop
        assert not task.cancelled()  # loop survived

    async def test_escalation_outside_ping_task_cancels_it(self):
        c = _client()
        calls = self._wire(c)
        fake = _FakeTask()
        c._ping_task = fake
        await c._ui_plus_full_reattach_and_retry("someCmd", "<b/>", False)
        assert calls == [True]  # normal caller: tear down + recreate ping task
        assert fake.cancelled_ is True
        assert c._ping_task is None


# H-2 — step() drops the target even when the step POST fails ------------------
@pytest.mark.asyncio
async def test_h2_step_discards_even_on_post_failure():
    c = _client()
    c._stopped_targets.add(UUID)
    c._user_visible_stops.add(UUID)
    c._last_stopped_target_id = UUID
    c._last_exception_by_target[UUID] = {"code": "1"}
    c._resolve_target_uuid = lambda t: UUID
    c._ensure_target_attached = AsyncMock()
    c._post = AsyncMock(side_effect=RuntimeError("target force-resumed"))
    with pytest.raises(RuntimeError):
        await c.step("Continue", UUID)
    # Ghost prevention: discarded from BOTH sets despite the POST failure.
    assert UUID not in c._stopped_targets
    assert UUID not in c._user_visible_stops
    assert UUID not in c._last_exception_by_target


# M-1 — _await_bp_stop keys off _user_visible_stops, not raw _stopped_targets --
@pytest.mark.asyncio
async def test_m1_await_ignores_stopped_not_user_visible():
    c = _client()
    c._stopped_targets.add(UUID)  # e.g. a draining suppressed logpoint stop
    c._stop_reason_by_target[UUID] = "breakpoint"
    # deliberately NOT in _user_visible_stops
    tid = await _await_bp_stop(c, timeout_sec=0.3)
    assert tid == ""


# M-3 — verdict engine: empty/error eval → INCONCLUSIVE; real mismatch wins ---
@pytest.mark.asyncio
class TestM3Verdict:
    async def test_empty_eval_is_inconclusive(self):
        c = _client()
        c.eval_expression = AsyncMock(return_value=[])  # evalExpr timed out
        v = await autonomy.evaluate_expect(c, UUID, {"Итог": "Истина"})
        assert v["status"] == "INCONCLUSIVE"
        assert v["checked"][0]["error"] is True

    async def test_definitive_mismatch_beats_inconclusive(self):
        c = _client()

        async def ev(expression, target_uuid, stack_level):
            return [] if expression == "A" else [{"resultValueInfo": {"pres": ""}}]

        c.eval_expression = AsyncMock(side_effect=ev)
        v = await autonomy.evaluate_expect(c, UUID, {"A": "1", "B": "X"})
        assert v["status"] == "FAIL"  # B's real mismatch not masked by A's error


def test_m3_pres_preferred_over_typed_boolean():
    # M-3: verdict compares presentations — pres «Истина» beats typed valueBoolean="true".
    pres = base64.b64encode("Истина".encode()).decode()
    res = [{"resultValueInfo": {"valueBoolean": "true", "pres": pres}}]
    assert autonomy._extract_eval_value(res) == "Истина"


# H-5 — degraded seed diagnosis when the exception window closed ---------------
def test_h5_build_seed_diagnosis_shape(monkeypatch):
    monkeypatch.setattr(
        autonomy.uuid_index, "get_source_info", lambda o, p: {"fqn": f"{o}.{p}", "file_path": "/x"}
    )
    stack = [_frame("outer", "p0", 1), _frame("inner", "p1", 42)]
    d = autonomy.build_seed_diagnosis({"code": "9", "message": "boom"}, stack)
    assert d["window_closed"] is True
    assert d["frames_inspected"] == []
    assert d["frames_total"] == 2
    assert d["fault_location"]["line"] == 42  # innermost = LAST frame (Ф-2)
    assert d["runtime_symptom"] == {"code": "9", "message": "boom"}
    assert len(d["propagation_path"]) == 2


# M-4 — drain_active awaits in-flight deferred logpoint tasks ------------------
@pytest.mark.asyncio
async def test_m4_drain_active_awaits_pending():
    done = []

    async def _slow():
        await asyncio.sleep(0.05)
        done.append(True)

    t = asyncio.create_task(_slow())
    logpoints._active_tasks.add(t)
    t.add_done_callback(logpoints._active_tasks.discard)
    pending = await logpoints.drain_active(timeout=1.0)
    assert pending == 1
    assert done == [True]  # awaited to completion, tail not truncated


# LOW — _extract_upstream ignores string literals + type after `Новый` --------
class TestUpstreamParsing:
    def test_string_literal_identifiers_not_upstream(self):
        up = autonomy._extract_upstream('"Итого по " + Контрагент', "Итог")
        assert "Контрагент" in up
        assert "Итого" not in up  # inside the string literal

    def test_type_after_novyi_not_upstream(self):
        up = autonomy._extract_upstream("Новый ТаблицаЗначений", "Т")
        assert up == []
