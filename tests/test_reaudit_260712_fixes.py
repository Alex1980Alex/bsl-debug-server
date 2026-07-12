"""Re-audit 260712 fixes: cross-feature seams found by the adversarial re-review
of W4'/W5' (M-5 class on A5/C4 arm, A5 finally-teardown, F-2 snapshot drain,
Ф-2 metrics innermost, XML-escape eval expressions).
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import mcp_debug_server as mds


def _mk_client(tmp_path):
    """Minimal client double for arm-path tests (pattern of test_a5_hypothesis)."""
    c = mds.RDBGClient.__new__(mds.RDBGClient)
    c._attached = True
    c._registered = True
    c.session_id = "sess"
    c._log_dir = tmp_path
    c._logpoints = {}
    c._set_breakpoints_cache = []
    c._line_offsets = {}
    c._hypothesis = None
    c._trace_var = None
    c._watchpoints = {}
    c._watch_last = {}
    c._watch_changes = []
    c._watch_run = None
    c.set_breakpoints = AsyncMock()
    c.set_break_on_next_statement = AsyncMock()
    c._push_bp_workspace = AsyncMock()
    return c


# --- M-5 class: A5 arm must skip lines owned by a foreign logpoint/BP ---------
@pytest.mark.asyncio
async def test_a5_arm_skips_foreign_logpoint(tmp_path, monkeypatch):
    client = _mk_client(tmp_path)
    # A3-trace (or user) already owns line 10
    client._logpoints[("o", "pid-x", 10)] = "user template"
    monkeypatch.setattr(mds, "_get_client", lambda: client)
    monkeypatch.setattr(mds, "_resolve_property_id", lambda mt, pid: ("ConfigModule", "pid-x"))
    res = json.loads(
        await mds.debug_hypothesis(
            assertions=[
                {"object_id": "o", "line": 10, "expr": "X"},   # collides → skipped
                {"object_id": "o", "line": 20, "expr": "Y"},   # armed
            ],
            phase="arm",
        )
    )
    assert res["status"] == "armed"
    assert res["assertion_count"] == 1
    assert res["skipped_collisions"][0]["line"] == 10
    # Foreign logpoint untouched
    assert client._logpoints[("o", "pid-x", 10)] == "user template"
    # Teardown set contains ONLY our key
    assert client._hypothesis["keys"] == {("o", "pid-x", 20)}


@pytest.mark.asyncio
async def test_a5_arm_all_collide_no_arm(tmp_path, monkeypatch):
    client = _mk_client(tmp_path)
    client._logpoints[("o", "pid-x", 10)] = "user template"
    monkeypatch.setattr(mds, "_get_client", lambda: client)
    monkeypatch.setattr(mds, "_resolve_property_id", lambda mt, pid: ("ConfigModule", "pid-x"))
    res = json.loads(
        await mds.debug_hypothesis(
            assertions=[{"object_id": "o", "line": 10, "expr": "X"}], phase="arm"
        )
    )
    assert res["status"] == "no_armable_assertions"
    client.set_break_on_next_statement.assert_not_awaited()
    assert client._hypothesis is None


# --- A5 collect: teardown must run even when judging raises ------------------
@pytest.mark.asyncio
async def test_a5_collect_teardown_in_finally(tmp_path, monkeypatch):
    client = _mk_client(tmp_path)
    client._hypothesis = {
        "assertions": [{"label": "#0", "key": ("o", "p", 5), "expr": "X", "expected": None, "line": 5}],
        "keys": {("o", "p", 5)},
        "armed_log_lines": 0,
    }
    client._logpoints[("o", "p", 5)] = "{X}"
    monkeypatch.setattr(mds, "_get_client", lambda: client)
    # Force an exception mid-judging: entries reader blows up
    monkeypatch.setattr(mds, "_a5_read_entries", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    res = json.loads(await mds.debug_hypothesis(phase="collect"))
    assert "error" in res  # graceful envelope
    # finally-teardown ran despite the exception
    assert client._hypothesis is None
    assert ("o", "p", 5) not in client._logpoints


# --- M-5 class: C4 watchpoint arm skips foreign lines ------------------------
@pytest.mark.asyncio
async def test_c4_arm_skips_foreign_bp(tmp_path, monkeypatch):
    client = _mk_client(tmp_path)
    client._set_breakpoints_cache = [{"object_id": "o", "property_id": "pid-x", "lines": [2]}]
    monkeypatch.setattr(mds, "_get_client", lambda: client)
    monkeypatch.setattr(mds, "_resolve_property_id", lambda mt, pid: ("ConfigModule", "pid-x"))
    src = tmp_path / "m.bsl"
    src.write_text(
        "Процедура Тест()\n    Ответ = 1;\n    Прочее = 0;\n    Ответ = 2;\nКонецПроцедуры\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(mds.uuid_index, "resolve_uuid", lambda oid, pid, **kw: src)
    res = json.loads(await mds.debug_set_watchpoint(name="Ответ", object_id="o"))
    assert res["status"] == "armed"
    # line 2 collides with the user BP → skipped; line 4 armed
    assert [s["line"] for s in res["skipped_collisions"]] == [2]
    assert [li["line"] for li in res["lines"]] == [4]
    # Foreign BP-cache entry untouched
    assert client._set_breakpoints_cache[0]["lines"] == [2]


@pytest.mark.asyncio
async def test_c4_arm_all_collide(tmp_path, monkeypatch):
    client = _mk_client(tmp_path)
    client._logpoints[("o", "pid-x", 2)] = "user"
    monkeypatch.setattr(mds, "_get_client", lambda: client)
    monkeypatch.setattr(mds, "_resolve_property_id", lambda mt, pid: ("ConfigModule", "pid-x"))
    src = tmp_path / "m.bsl"
    src.write_text("Процедура Т()\n    Ответ = 1;\nКонецПроцедуры\n", encoding="utf-8")
    monkeypatch.setattr(mds.uuid_index, "resolve_uuid", lambda oid, pid, **kw: src)
    res = json.loads(await mds.debug_set_watchpoint(name="Ответ", object_id="o"))
    assert res["status"] == "no_watchable_lines"
    assert client._watch_run is None


# --- F-2: snapshot drain -------------------------------------------------------
@pytest.mark.asyncio
async def test_drain_snapshot_tasks_awaits_pending():
    done = []

    async def slow_write():
        await asyncio.sleep(0.05)
        done.append(1)

    t = asyncio.create_task(slow_write())
    mds._snapshot_tasks.add(t)
    t.add_done_callback(mds._snapshot_tasks.discard)
    still = await mds._drain_snapshot_tasks(timeout=2.0)
    assert still == 0
    assert done == [1]


# --- Ф-2 metrics: stop metrics keyed off INNERMOST frame ---------------------
_T1 = "11111111-2222-3333-4444-555555555555"  # _extract_target_id requires UUID shape


@pytest.mark.asyncio
async def test_stop_metrics_innermost_frame(tmp_path):
    client = _mk_client(tmp_path)
    client._stopped_targets = set()
    client._user_visible_stops = set()
    client._last_stack_by_target = {}
    client._stop_reason_by_target = {}
    client._last_exception_by_target = {}
    client._known_attached_targets = {_T1}
    client._attached_pending = set()
    client._coverage_tracked = {}
    client._hit_conditions = {}
    client._break_on_next_armed = False
    client._break_on_next_silent_arm = False
    client._capture_mode = False
    client._stop_events = []
    client._bp_fire_count = 0
    client._bp_by_location = {}
    client._rphosts_seen = set()
    client._recording_enabled = False
    client._exception_bp_filters = []
    client._bp_stop_event = None
    client._bp_stop_event_loop = None
    client._last_visible_stop_ts = 0.0
    # outermost frame line 1 (entry), INNERMOST (BP) frame line 70
    stack = [
        {"moduleID": {"objectID": "entry"}, "lineNo": 1},
        {"moduleID": {"objectID": "target-mod"}, "lineNo": 70},
    ]
    await client._handle_command(
        {"cmdId": "callStackFormed", "targetID": {"id": _T1}, "callStack": stack, "stopByBP": "true"}
    )
    assert client._stop_events[-1]["lineNo"] == 70  # innermost, not entry-point
    assert "target-mod:70" in client._bp_by_location


# --- XML-escape eval expressions ----------------------------------------------
@pytest.mark.asyncio
async def test_eval_expression_escapes_xml(tmp_path):
    client = _mk_client(tmp_path)
    client._attached_targets = {"t1"}
    client._last_stopped_target_id = "t1"  # underlying attr (property has no setter)
    client._pending_evals = {}
    client._eval_count = 0
    captured = {}

    async def fake_post(url, body):
        captured["body"] = body
        import xml.etree.ElementTree as ET

        # must be well-formed XML despite `<`/`&` in the BSL expression
        ET.fromstring(body)
        return ET.fromstring("<r/>")

    client._post = fake_post
    client._ensure_target_attached = AsyncMock()
    client._resolve_target_uuid = lambda t: "t1"
    client._base_fields = lambda: ""
    try:
        await client.eval_expression(
            expression="?(А<Б И В>Г, 1, 0)", target_uuid="t1", async_wait_timeout=0
        )
    except Exception:
        pass  # parse of fake response may legitimately fail downstream
    assert "&lt;" in captured["body"] and "&amp;" not in captured["body"].split("expression")[0]
    assert "А<Б" not in captured["body"]
