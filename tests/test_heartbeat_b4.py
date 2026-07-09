"""Unit tests for B4 — dbgs heartbeat + auto-reattach recovery (roadmap 260708).

Covers:
- _heartbeat_record: streak tracking, threshold → degraded → reconnect
- _maybe_reconnect: cooldown throttle, success resets degraded
- _attempt_reconnect: success path + loop-survival guarantee (flags restored to
  True on failure / attach-raise so the ping-loop never dies)
- get_target_state surfaces the recovery snapshot

Strategy: real RDBGClient with _post + reconnect primitives patched (no network).
Mirrors test_longpoll_b3 / test_root_cause_a2.
"""

from __future__ import annotations

import asyncio
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import mcp_debug_server as mds
from mcp_debug_server import RDBGClient


@pytest.fixture(autouse=True)
def _no_session_fs(monkeypatch):
    # Real detach() calls _clear_active_session; keep tests off the filesystem.
    monkeypatch.setattr(mds, "_clear_active_session", lambda: None)
    monkeypatch.setattr(mds, "_persist_active_session", lambda cl: None)


def _make_client() -> RDBGClient:
    c = RDBGClient(debug_url="http://localhost:1550", infobase_alias="TestDB")
    c._post = AsyncMock(return_value=ET.Element("empty"))
    return c


def _wire_reconnect(c, registered=True):
    """Patch the re-attach primitives so _attempt_reconnect runs without network.

    IMPORTANT: `detach` is NOT mocked — the real detach(cancel_ping=False) path is
    exercised (that's where the ping-task-cancel bug lived). Only `_post` (mocked
    in _make_client) and the handshake methods are stubbed. `attach` mirrors the
    real one: sets _attached=True + _registered based on the RDBG result.
    """
    async def _fake_attach(*a, **k):
        c._attached = True
        c._registered = registered  # real attach: _registered = (result=="registered")

    c.attach = AsyncMock(side_effect=_fake_attach)
    c.init_settings = AsyncMock()
    c.clear_break_on_next_statement = AsyncMock()
    c.set_auto_attach_settings = AsyncMock()
    c._reapply_bp_workspace = AsyncMock()


# ---------------------------------------------------------------------------
# _heartbeat_record
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestHeartbeatRecord:
    async def test_ok_resets_streak_and_degraded(self):
        c = _make_client()
        c._recovery["consecutive_ping_failures"] = 2
        c._recovery["degraded"] = True
        await c._heartbeat_record(True)
        assert c._recovery["consecutive_ping_failures"] == 0
        assert c._recovery["degraded"] is False

    async def test_fail_below_threshold_no_reconnect(self):
        c = _make_client()
        c._maybe_reconnect = AsyncMock()
        await c._heartbeat_record(False)
        await c._heartbeat_record(False)  # 2 < 3
        assert c._recovery["consecutive_ping_failures"] == 2
        assert c._recovery["degraded"] is False
        c._maybe_reconnect.assert_not_awaited()

    async def test_fail_at_threshold_triggers_reconnect(self):
        c = _make_client()
        c._maybe_reconnect = AsyncMock()
        for _ in range(RDBGClient.HEARTBEAT_FAIL_THRESHOLD):
            await c._heartbeat_record(False)
        assert c._recovery["consecutive_ping_failures"] == RDBGClient.HEARTBEAT_FAIL_THRESHOLD
        assert c._recovery["degraded"] is True
        c._maybe_reconnect.assert_awaited_once()

    async def test_recovery_after_failures_logs_and_resets(self):
        c = _make_client()
        c._maybe_reconnect = AsyncMock()
        for _ in range(RDBGClient.HEARTBEAT_FAIL_THRESHOLD):
            await c._heartbeat_record(False)
        await c._heartbeat_record(True)  # ping recovers
        assert c._recovery["consecutive_ping_failures"] == 0
        assert c._recovery["degraded"] is False


# ---------------------------------------------------------------------------
# _maybe_reconnect — cooldown
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestMaybeReconnect:
    async def test_cooldown_skips_attempt(self):
        c = _make_client()
        c._attempt_reconnect = AsyncMock(return_value=True)
        c._recovery["last_reconnect_ts"] = asyncio.get_running_loop().time()  # just now
        ok = await c._maybe_reconnect()
        assert ok is False
        c._attempt_reconnect.assert_not_awaited()

    async def test_past_cooldown_attempts_and_resets(self):
        c = _make_client()
        c._attempt_reconnect = AsyncMock(return_value=True)
        c._recovery["degraded"] = True
        c._recovery["consecutive_ping_failures"] = 5
        c._recovery["last_reconnect_ts"] = asyncio.get_running_loop().time() - 100  # old
        ok = await c._maybe_reconnect()
        assert ok is True
        c._attempt_reconnect.assert_awaited_once()
        assert c._recovery["last_reconnect_ok"] is True
        assert c._recovery["degraded"] is False
        assert c._recovery["consecutive_ping_failures"] == 0
        assert c._recovery["reconnect_attempts"] == 1

    async def test_failed_attempt_keeps_degraded(self):
        c = _make_client()
        c._attempt_reconnect = AsyncMock(return_value=False)
        c._recovery["degraded"] = True
        ok = await c._maybe_reconnect()
        assert ok is False
        assert c._recovery["last_reconnect_ok"] is False
        assert c._recovery["degraded"] is True  # still degraded — will retry after cooldown

    async def test_attempt_exception_swallowed(self):
        c = _make_client()
        c._attempt_reconnect = AsyncMock(side_effect=RuntimeError("boom"))
        ok = await c._maybe_reconnect()
        assert ok is False
        assert c._recovery["last_reconnect_ok"] is False


# ---------------------------------------------------------------------------
# _attempt_reconnect — success + loop-survival guarantee
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestAttemptReconnect:
    async def test_success_rehandshakes_and_reapplies(self):
        c = _make_client()
        _wire_reconnect(c, registered=True)
        old_sid = c.session_id
        ok = await c._attempt_reconnect()
        assert ok is True
        c.attach.assert_awaited_once()
        c.init_settings.assert_awaited_once()
        c._reapply_bp_workspace.assert_awaited_once()
        assert c.session_id != old_sid  # fresh session
        assert c._attached is True and c._registered is True

    async def test_not_registered_restores_keepalive_flags(self):
        c = _make_client()
        _wire_reconnect(c, registered=False)  # attach → _registered stays False
        ok = await c._attempt_reconnect()
        assert ok is False
        # finally restores flags so the ping-loop (gate _attached and _registered) survives
        assert c._attached is True and c._registered is True
        c.init_settings.assert_not_awaited()  # bailed before handshake

    async def test_attach_raises_restores_flags_and_propagates(self):
        c = _make_client()
        c.attach = AsyncMock(side_effect=RuntimeError("dbgs down"))  # real detach runs first
        with pytest.raises(RuntimeError):
            await c._attempt_reconnect()
        # finally ran despite the raise → loop stays alive
        assert c._attached is True and c._registered is True

    async def test_does_not_cancel_live_ping_task(self):
        # Regression (code-verify FAIL iter-1): _attempt_reconnect goes through
        # detach(), whose DEFAULT cancels _ping_task. Running inside the loop that
        # kills the heartbeat (CancelledError → _ping_loop exits forever). The fix
        # is detach(cancel_ping=False) — this asserts the live task is NOT cancelled.
        c = _make_client()
        _wire_reconnect(c, registered=True)
        fake_task = MagicMock()
        fake_task.done.return_value = False  # alive — the dangerous case
        c._ping_task = fake_task
        await c._attempt_reconnect()
        fake_task.cancel.assert_not_called()  # would fail with the pre-fix detach()
        assert c._ping_task is fake_task


# ---------------------------------------------------------------------------
# recovery surfaced in session snapshot + end-to-end
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestRecoverySurface:
    async def test_get_target_state_includes_recovery(self):
        c = _make_client()
        c._recovery["degraded"] = True
        c._recovery["reconnect_attempts"] = 2
        snap = await c.get_target_state(None)
        assert "recovery" in snap
        assert snap["recovery"]["degraded"] is True
        assert snap["recovery"]["reconnect_attempts"] == 2

    async def test_end_to_end_sustained_failure_then_reconnect(self, monkeypatch):
        # Real _heartbeat_record → _maybe_reconnect → _attempt_reconnect chain.
        c = _make_client()
        _wire_reconnect(c, registered=True)
        monkeypatch.setattr(mds, "_persist_active_session", lambda cl: None)
        for _ in range(RDBGClient.HEARTBEAT_FAIL_THRESHOLD):
            await c._heartbeat_record(False)
        assert c._recovery["reconnect_attempts"] == 1
        assert c._recovery["last_reconnect_ok"] is True
        assert c._recovery["degraded"] is False
        assert c._recovery["consecutive_ping_failures"] == 0
