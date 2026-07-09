"""Unit tests for B3 — event-driven long-poll wait (roadmap 260708 §7.6).

Covers:
- RDBGClient._get_stop_event / _signal_bp_stop (loop-bound Event lifecycle)
- _await_bp_stop (predicate == prior poll-loop: reason="breakpoint" + 0.15s
  debounce; event-driven wakeup; ≤1.0s safety-net cap)
- _handle_command signals the Event on a user-visible BP stop
- debug_autotrace collect uses the event-driven waiter (hit / NO_HIT)

Strategy: real RDBGClient with _post patched (no network), autonomy +
client.step patched for the tool-level collect tests. Mirrors the mock style
of test_mcp_debug_server.py.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import mcp_debug_server as mds
from mcp_debug_server import RDBGClient, _await_bp_stop

GOOD_UUID = "11111111-2222-3333-4444-555555555555"
OTHER_UUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def _make_client() -> RDBGClient:
    c = RDBGClient(debug_url="http://localhost:1550", infobase_alias="TestDB")
    c._post = AsyncMock(return_value=ET.Element("empty"))
    return c


# ---------------------------------------------------------------------------
# _get_stop_event / _signal_bp_stop
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestStopEvent:
    async def test_get_stop_event_same_instance_within_loop(self):
        c = _make_client()
        ev1 = c._get_stop_event()
        ev2 = c._get_stop_event()
        assert ev1 is ev2
        assert isinstance(ev1, asyncio.Event)

    async def test_get_stop_event_recreated_on_loop_change(self):
        c = _make_client()
        ev1 = c._get_stop_event()
        # Simulate a different loop (HMR restart) — accessor must rebind.
        c._bp_stop_event_loop = object()  # sentinel != running loop
        ev2 = c._get_stop_event()
        assert ev2 is not ev1

    async def test_signal_sets_event(self):
        c = _make_client()
        assert not c._get_stop_event().is_set()
        c._signal_bp_stop()
        assert c._get_stop_event().is_set()


def test_signal_no_running_loop_is_noop():
    # Called outside a running loop → best-effort no-op, no exception.
    c = _make_client()
    c._signal_bp_stop()
    assert c._bp_stop_event is None


# ---------------------------------------------------------------------------
# _await_bp_stop — predicate + debounce + event-driven wakeup
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestAwaitBpStop:
    async def test_returns_present_breakpoint_target(self):
        c = _make_client()
        c._stopped_targets.add(GOOD_UUID)
        c._stop_reason_by_target[GOOD_UUID] = "breakpoint"
        t0 = time.monotonic()
        tid = await _await_bp_stop(c, timeout_sec=5.0)
        assert tid == GOOD_UUID
        # only the 0.15s debounce, nowhere near the 5s timeout
        assert time.monotonic() - t0 < 0.6

    async def test_timeout_returns_empty(self):
        c = _make_client()
        t0 = time.monotonic()
        tid = await _await_bp_stop(c, timeout_sec=0.3)
        assert tid == ""
        assert time.monotonic() - t0 >= 0.3

    async def test_ignores_step_reason(self):
        c = _make_client()
        c._stopped_targets.add(GOOD_UUID)
        c._stop_reason_by_target[GOOD_UUID] = "step"  # system halt, not user BP
        tid = await _await_bp_stop(c, timeout_sec=0.3)
        assert tid == ""

    async def test_debounce_drops_transient_target(self):
        c = _make_client()
        c._stopped_targets.add(GOOD_UUID)
        c._stop_reason_by_target[GOOD_UUID] = "breakpoint"

        async def _drain():
            await asyncio.sleep(0.05)  # remove before the 0.15 debounce re-check
            c._stopped_targets.discard(GOOD_UUID)

        drainer = asyncio.create_task(_drain())
        tid = await _await_bp_stop(c, timeout_sec=0.4)
        await drainer
        assert tid == ""  # transient stop debounced away

    async def test_event_driven_wakeup_is_prompt(self):
        c = _make_client()

        async def _fire():
            await asyncio.sleep(0.05)
            c._stopped_targets.add(GOOD_UUID)
            c._stop_reason_by_target[GOOD_UUID] = "breakpoint"
            c._signal_bp_stop()

        firer = asyncio.create_task(_fire())
        t0 = time.monotonic()
        tid = await _await_bp_stop(c, timeout_sec=5.0)
        elapsed = time.monotonic() - t0
        await firer
        assert tid == GOOD_UUID
        # signal(0.05) + immediate wakeup + debounce(0.15) ≈ 0.2s. Without the
        # signal the target would only surface after the 1.0s safety-net cap.
        assert elapsed < 0.5

    async def test_safety_net_finds_target_without_signal(self):
        # Defense-in-depth: even if the Event is never set, the ≤1.0s cap
        # re-checks the predicate (state is authoritative).
        c = _make_client()

        async def _fire_silent():
            await asyncio.sleep(0.05)
            c._stopped_targets.add(GOOD_UUID)
            c._stop_reason_by_target[GOOD_UUID] = "breakpoint"
            # deliberately NO _signal_bp_stop()

        firer = asyncio.create_task(_fire_silent())
        tid = await _await_bp_stop(c, timeout_sec=3.0)
        await firer
        assert tid == GOOD_UUID


# ---------------------------------------------------------------------------
# _handle_command signals the Event on a user-visible BP stop
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestHandleCommandSignals:
    async def test_breakpoint_stop_signals_event(self):
        c = _make_client()
        c._get_stop_event().clear()
        await c._handle_command(
            {
                "cmdId": "callStackFormed",
                "targetID": GOOD_UUID,
                "callStack": [{"_tag": "frame", "line": "70"}],
                "stopByBP": "true",
            }
        )
        assert GOOD_UUID in c._stopped_targets
        assert c._get_stop_event().is_set()

    async def test_step_stop_does_not_signal_event(self):
        c = _make_client()
        c._get_stop_event().clear()
        await c._handle_command(
            {
                "cmdId": "callStackFormed",
                "targetID": GOOD_UUID,
                "callStack": [{"_tag": "frame"}],
                "stopByBP": "false",  # system/step stop → must not wake collect
            }
        )
        assert not c._get_stop_event().is_set()


# ---------------------------------------------------------------------------
# debug_autotrace collect uses the event-driven waiter
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestAutotraceCollect:
    async def test_collect_hit_returns_bundle_and_releases(self, monkeypatch):
        c = _make_client()
        c._attached = True
        c._registered = True
        c._stopped_targets.add(GOOD_UUID)
        c._stop_reason_by_target[GOOD_UUID] = "breakpoint"
        c.step = AsyncMock()
        monkeypatch.setattr(mds, "_client", c, raising=False)
        monkeypatch.setattr(mds, "_get_client", lambda: c)
        monkeypatch.setattr(
            mds.autonomy,
            "build_frame_bundle",
            AsyncMock(return_value={"line": 70, "variables": {}, "stack": []}),
        )

        raw = await mds.debug_autotrace(phase="collect", timeout_sec=2.0)
        data = json.loads(raw)
        assert data["raw"]["hit"] is True
        assert data["raw"]["line"] == 70
        assert data["verdict"] is None  # no expect passed
        c.step.assert_awaited()  # Continue in finally released the rphost

    async def test_collect_no_hit_returns_verdict(self, monkeypatch):
        c = _make_client()
        c._attached = True
        c._registered = True
        c.step = AsyncMock()
        monkeypatch.setattr(mds, "_client", c, raising=False)
        monkeypatch.setattr(mds, "_get_client", lambda: c)

        raw = await mds.debug_autotrace(
            phase="collect", expect={"Итог": "Истина"}, timeout_sec=0.3
        )
        data = json.loads(raw)
        assert data["raw"]["hit"] is False
        assert data["verdict"]["status"] == "NO_HIT"
