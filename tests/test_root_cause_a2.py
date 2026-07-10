"""Unit tests for A2 — debug_root_cause diagnosis-record (roadmap 260708 §7.6).

Covers:
- autonomy.extract_exception_symptom (RDBG exception dict shapes)
- autonomy.build_diagnosis_record (fault location / symptom / propagation path /
  bounded observed values)
- _await_bp_stop(reasons=("exception",)) + B3 default still ignores exceptions
- _handle_command rteProcessing signals the stop-event
- debug_root_cause tool: arm / collect hit (real composer) / NO_HIT / errors

Strategy: FakeClient / real RDBGClient with _post patched; uuid_index
monkeypatched to isolate from real EDT export. Mirrors test_autonomy.py +
test_longpoll_b3.py.
"""

from __future__ import annotations

import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import autonomy
import mcp_debug_server as mds
import uuid_index
from mcp_debug_server import RDBGClient, _await_bp_stop

TGT = "11111111-2222-3333-4444-555555555555"


def _frame(oid, pid, line):
    return {"moduleID": {"objectID": oid, "propertyID": pid}, "lineNo": line}


def _make_client() -> RDBGClient:
    c = RDBGClient(debug_url="http://localhost:1550", infobase_alias="TestDB")
    c._post = AsyncMock(return_value=ET.Element("empty"))
    return c


# ---------------------------------------------------------------------------
# extract_exception_symptom
# ---------------------------------------------------------------------------


class TestExtractSymptom:
    def test_code_and_info(self):
        s = autonomy.extract_exception_symptom({"code": "42", "info": "Деление на ноль"})
        assert s == {"code": "42", "message": "Деление на ноль"}

    def test_messagetext_variant(self):
        s = autonomy.extract_exception_symptom({"messageText": "boom"})
        assert s["message"] == "boom"
        assert s["code"] == ""

    def test_non_dict(self):
        assert autonomy.extract_exception_symptom(None) == {"code": "", "message": ""}
        assert autonomy.extract_exception_symptom("x") == {"code": "", "message": ""}

    def test_empty(self):
        assert autonomy.extract_exception_symptom({}) == {"code": "", "message": ""}


# ---------------------------------------------------------------------------
# build_diagnosis_record
# ---------------------------------------------------------------------------


class DiagClient:
    def __init__(self, stack, exc, locals_result=None):
        self._last_stack_by_target = {TGT: stack}
        self._last_exception_by_target = {TGT: exc}
        self._locals = locals_result if locals_result is not None else []

    async def get_call_stack(self, target_uuid=None):
        return self._last_stack_by_target.get(target_uuid, [])

    async def eval_locals_auto(self, target_uuid=None, stack_level=0):
        return self._locals


@pytest.fixture(autouse=True)
def _iso_uuid(monkeypatch):
    # Isolate from real EDT export: resolved source = synthetic, no file read.
    monkeypatch.setattr(
        uuid_index,
        "get_source_info",
        lambda o, p: ({"fqn": f"Mod.{o}", "file_path": f"/{o}.bsl", "exists": False} if o else None),
    )
    monkeypatch.setattr(uuid_index, "resolve_uuid", lambda o, p: None)


@pytest.mark.asyncio
class TestBuildDiagnosisRecord:
    async def test_full_record(self):
        stack = [_frame("o0", "p0", 10), _frame("o1", "p1", 20), _frame("o2", "p2", 30)]
        c = DiagClient(stack, {"code": "7", "info": "boom"}, locals_result=[{"name": "X"}])
        rec = await autonomy.build_diagnosis_record(c, TGT, max_frames=3, context_radius=2)
        # symptom
        assert rec["runtime_symptom"] == {"code": "7", "message": "boom"}
        # fault = innermost frame (stack_level 0 → stack[-1], line 30, oid o2)
        assert rec["fault_location"]["line"] == 30
        assert rec["fault_location"]["fqn"] == "Mod.o2"
        # propagation path = full stack outermost-first
        assert [p["line"] for p in rec["propagation_path"]] == [10, 20, 30]
        assert rec["frames_total"] == 3
        assert rec["frames_bounded"] is False
        assert len(rec["frames_inspected"]) == 3

    async def test_bounded_frames(self):
        stack = [_frame(f"o{i}", f"p{i}", (i + 1) * 10) for i in range(5)]
        c = DiagClient(stack, {"info": "x"})
        rec = await autonomy.build_diagnosis_record(c, TGT, max_frames=2)
        assert rec["frames_total"] == 5
        assert rec["frames_bounded"] is True  # 2 < 5 — truncation surfaced, not silent
        assert len(rec["frames_inspected"]) == 2
        assert len(rec["propagation_path"]) == 5  # full path always present

    async def test_empty_stack_degrades(self):
        c = DiagClient([], {"info": "x"})
        rec = await autonomy.build_diagnosis_record(c, TGT)
        assert rec["fault_location"] is None
        assert rec["frames_inspected"] == []
        assert rec["frames_total"] == 0
        assert rec["runtime_symptom"]["message"] == "x"


# ---------------------------------------------------------------------------
# _await_bp_stop reasons param
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestAwaitReasons:
    async def test_exception_reason_matches(self):
        c = _make_client()
        c._stopped_targets.add(TGT)
        c._user_visible_stops.add(TGT)  # M-1: source of truth for _await_bp_stop
        c._stop_reason_by_target[TGT] = "exception"
        tid = await _await_bp_stop(c, timeout_sec=5.0, reasons=("exception",))
        assert tid == TGT

    async def test_default_breakpoint_ignores_exception(self):
        # B3 back-compat: default reasons=("breakpoint",) must NOT match exceptions.
        c = _make_client()
        c._stopped_targets.add(TGT)
        c._stop_reason_by_target[TGT] = "exception"
        tid = await _await_bp_stop(c, timeout_sec=0.3)
        assert tid == ""


# ---------------------------------------------------------------------------
# _handle_command rteProcessing signals the stop-event
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestRteSignals:
    async def test_exception_stop_signals_event(self):
        c = _make_client()
        c._get_stop_event().clear()
        await c._handle_command(
            {
                "cmdId": "rteProcessing",
                "targetID": TGT,
                "callStack": [_frame("o", "p", 5)],
                "exception": {"code": "1", "info": "boom"},
            }
        )
        assert c._stop_reason_by_target[TGT] == "exception"
        assert c._get_stop_event().is_set()

    async def test_filtered_exception_no_signal(self):
        # An exception suppressed by a non-matching filter must NOT wake waiters.
        c = _make_client()
        c._get_stop_event().clear()
        c.step = AsyncMock()  # suppress path calls Continue
        c._exception_bp_filters.append({"message_pattern": "deadlock", "module_pattern": ""})
        await c._handle_command(
            {
                "cmdId": "rteProcessing",
                "targetID": TGT,
                "callStack": [{"presentation": "SomeModule"}],
                "exception": {"info": "Деление на ноль"},  # does not match "deadlock"
            }
        )
        assert not c._get_stop_event().is_set()

    async def test_filter_matches_info_message(self):
        # Fix 2026-07-10 (A2 code-verify): message_pattern must match the live
        # `info` field. A matching filter → NOT suppressed → event signalled.
        c = _make_client()
        c._get_stop_event().clear()
        c.step = AsyncMock()
        c._exception_bp_filters.append({"message_pattern": "деление", "module_pattern": ""})
        await c._handle_command(
            {
                "cmdId": "rteProcessing",
                "targetID": TGT,
                "callStack": [_frame("o", "p", 5)],
                "exception": {"info": "Деление на ноль"},  # matches "деление" (ci)
            }
        )
        assert c._get_stop_event().is_set()
        c.step.assert_not_awaited()  # not suppressed → no auto-Continue


# ---------------------------------------------------------------------------
# debug_root_cause tool
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestDebugRootCause:
    async def test_not_connected(self, monkeypatch):
        c = _make_client()
        c._attached = False
        monkeypatch.setattr(mds, "_get_client", lambda: c)
        out = json.loads(await mds.debug_root_cause(phase="collect"))
        assert out["error_type"] == "not_connected"

    async def test_bad_phase(self, monkeypatch):
        c = _make_client()
        c._attached = True
        c._registered = True
        monkeypatch.setattr(mds, "_get_client", lambda: c)
        out = json.loads(await mds.debug_root_cause(phase="bogus"))
        assert out["error_type"] == "bad_phase"

    async def test_arm_sets_filter_and_arms(self, monkeypatch):
        c = _make_client()
        c._attached = True
        c._registered = True
        c.set_break_on_next_statement = AsyncMock(return_value=True)
        monkeypatch.setattr(mds, "_get_client", lambda: c)
        out = json.loads(
            await mds.debug_root_cause(phase="arm", exception_message="деление", exception_module="гкс_")
        )
        assert out["status"] == "armed"
        assert out["exception_filter"] == {"message_pattern": "деление", "module_pattern": "гкс_"}
        assert c._exception_bp_filters[-1]["message_pattern"] == "деление"
        c.set_break_on_next_statement.assert_awaited_once()

    async def test_arm_without_filter_no_pollution(self, monkeypatch):
        c = _make_client()
        c._attached = True
        c._registered = True
        c.set_break_on_next_statement = AsyncMock(return_value=True)
        monkeypatch.setattr(mds, "_get_client", lambda: c)
        out = json.loads(await mds.debug_root_cause(phase="arm"))
        assert out["exception_filter"] is None
        assert c._exception_bp_filters == []  # no filter added when none requested

    async def test_collect_hit_builds_record_and_releases(self, monkeypatch):
        stack = [_frame("o0", "p0", 10), _frame("o1", "p1", 22)]
        c = _make_client()
        c._attached = True
        c._registered = True
        c._stopped_targets.add(TGT)
        c._user_visible_stops.add(TGT)  # M-1
        c._stop_reason_by_target[TGT] = "exception"
        c._last_stack_by_target[TGT] = stack
        c._last_exception_by_target[TGT] = {"code": "9", "info": "деление на ноль"}
        c.eval_locals_auto = AsyncMock(return_value=[{"name": "Делитель", "presentation": "0"}])
        c.step = AsyncMock()
        monkeypatch.setattr(mds, "_get_client", lambda: c)
        out = json.loads(await mds.debug_root_cause(phase="collect", timeout_sec=2.0))
        assert out["raw"]["hit"] is True
        d = out["diagnosis"]
        assert d["runtime_symptom"] == {"code": "9", "message": "деление на ноль"}
        assert d["fault_location"]["line"] == 22  # innermost
        assert d["frames_total"] == 2
        c.step.assert_awaited()  # Continue released the rphost

    async def test_collect_no_hit(self, monkeypatch):
        c = _make_client()
        c._attached = True
        c._registered = True
        c.step = AsyncMock()
        monkeypatch.setattr(mds, "_get_client", lambda: c)
        out = json.loads(await mds.debug_root_cause(phase="collect", timeout_sec=0.3))
        assert out["raw"]["hit"] is False
        assert out["diagnosis"] is None
