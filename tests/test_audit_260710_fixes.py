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
    assert pending == 0  # completed within the bounded wait → nothing still pending
    assert done == [True]  # awaited to completion, tail not truncated


@pytest.mark.asyncio
async def test_m4_drain_active_reports_still_pending_after_timeout():
    async def _too_slow():
        await asyncio.sleep(5.0)

    t = asyncio.create_task(_too_slow())
    logpoints._active_tasks.add(t)
    t.add_done_callback(logpoints._active_tasks.discard)
    try:
        pending = await logpoints.drain_active(timeout=0.05)
        assert pending == 1  # exceeded the bounded wait → still pending, tail may be late
    finally:
        t.cancel()


# LOW — _extract_upstream ignores string literals + type after `Новый` --------
class TestUpstreamParsing:
    def test_string_literal_identifiers_not_upstream(self):
        up = autonomy._extract_upstream('"Итого по " + Контрагент', "Итог")
        assert "Контрагент" in up
        assert "Итого" not in up  # inside the string literal

    def test_type_after_novyi_not_upstream(self):
        up = autonomy._extract_upstream("Новый ТаблицаЗначений", "Т")
        assert up == []


# Review 260710 — follow-up fixes -------------------------------------------
class TestReviewFollowups:
    def test_literal_plus_trailing_comment_not_truncated(self):
        # BLOCKER regression: length-preserving _strip_bsl_strings keeps `//` index
        # aligned so the RHS isn't cut mid-literal.
        src = ['Статус = "Черновик"; // начальный']
        out = autonomy.find_assignment_lines(src, "Статус")
        assert len(out) == 1
        assert out[0]["rhs"] == '"Черновик"'  # full literal, not truncated
        assert out[0]["upstream"] == []  # no garbage from inside the string

    def test_url_in_literal_not_split(self):
        up = autonomy._extract_upstream('"http://x" + Хост', "Адрес")
        assert up == ["Хост"]  # `//` inside the literal doesn't cut the RHS

    def test_empty_pres_falls_through_to_typed(self):
        # M-3 review: empty pres must not shadow a real typed value.
        res = [{"resultValueInfo": {"valueDecimal": "0", "pres": ""}}]
        assert autonomy._extract_eval_value(res) == "0"


@pytest.mark.asyncio
async def test_review_suppress_fail_does_not_seed_ghost():
    # Stык M-1 × H-2: an exception-filter suppress whose step("Continue") FAILS must
    # not leave a "visible but gone" target nor seed a ghost diagnosis.
    c = _client()
    c._exception_bp_filters = [{"message_pattern": "zzz", "module_pattern": ""}]  # won't match "boom"
    c._resolve_target_uuid = lambda t: t
    c._ensure_target_attached = AsyncMock()
    c._post = AsyncMock(side_effect=RuntimeError("resumed"))  # step POST fails → step-finally discards
    await c._handle_command(
        {
            "cmdId": "rteProcessing",
            "targetID": "t",
            "callStack": [_frame("o", "p", 5)],
            "exception": {"code": "1", "info": "boom"},
        }
    )
    assert "t" not in c._user_visible_stops
    assert c._recent_exceptions == []


@pytest.mark.asyncio
async def test_review_h1_finally_restores_flags_on_failed_attach_in_ping_task():
    # H-1 failure-path: a failed attach INSIDE _ping_task must restore the liveness
    # flags so `while _attached and _registered` keeps the heartbeat alive.
    c = _client()
    c.detach = AsyncMock(return_value=True)
    c.attach = AsyncMock(side_effect=RuntimeError("dbgs down"))

    async def run():
        c._ping_task = asyncio.current_task()
        with pytest.raises(RuntimeError):
            await c._ui_plus_full_reattach_and_retry("pingDebugUIParams", "<b/>", True)

    await asyncio.create_task(run())
    assert c._attached is True and c._registered is True


@pytest.mark.asyncio
async def test_review_m6_stale_stop_allows_reconnect():
    import time as _t

    c = _client()
    c._stopped_targets.add("t")
    c._last_visible_stop_ts = 0.0  # ancient → stale
    c._attempt_reconnect = AsyncMock(return_value=True)
    ok = await c._maybe_reconnect()
    assert ok is True
    c._attempt_reconnect.assert_awaited()

    c2 = _client()
    c2._stopped_targets.add("t")
    c2._last_visible_stop_ts = _t.time()  # fresh → protected
    c2._attempt_reconnect = AsyncMock(return_value=True)
    ok2 = await c2._maybe_reconnect()
    assert ok2 is False
    c2._attempt_reconnect.assert_not_awaited()


class _CollClient:
    _attached = True
    _registered = True
    last_stopped_target_id = "tgt"

    def __init__(self, type_name):
        self._type = type_name

    async def get_targets(self):
        return []

    async def eval_expression(self, expression, target_uuid=None, stack_level=0):
        return [{"presentation": self._type if expression.startswith("ТипЗнч") else "0"}]

    async def eval_local_variables(self, target_uuid=None, stack_level=0, expressions=None):
        return [{"name": e} for e in (expressions or [])]


@pytest.mark.asyncio
async def test_m10_sootvetstvie_unpageable(monkeypatch):
    import mcp_debug_server as mds

    monkeypatch.setattr(mds, "_get_client", lambda: _CollClient("Соответствие"))
    out = __import__("json").loads(await mds.debug_collection_page("М", start=0, count=5))
    assert out.get("error_type") == "unpageable_type"


@pytest.mark.asyncio
async def test_m10_fixedmap_en_unpageable(monkeypatch):
    import mcp_debug_server as mds

    monkeypatch.setattr(mds, "_get_client", lambda: _CollClient("FixedMap"))
    out = __import__("json").loads(await mds.debug_collection_page("М", start=0, count=5))
    assert out.get("error_type") == "unpageable_type"


@pytest.mark.asyncio
async def test_review_h4_drain_awaits_clear_task():
    c = _client()
    order = []

    async def _clear():
        await asyncio.sleep(0.02)
        order.append("clear")

    c._hmr_clear_task = asyncio.create_task(_clear())
    await c._drain_hmr_clear()
    assert order == ["clear"]  # awaited to completion
    assert c._hmr_clear_task is None
