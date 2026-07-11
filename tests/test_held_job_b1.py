"""B1 (roadmap 260708, ADR-049) unit tests: persistent JOB-контекст.

Covers held_job pure BSL builders + debug_launch_held_job / debug_release_held_job
/ debug_step(Continue) release integration (two-phase transport, no MCP_ONEC_* env).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import held_job
import mcp_debug_server as mds


# --- pure builders --------------------------------------------------------
class TestBuilders:
    def test_bsl_string_escapes_quotes(self):
        assert held_job._bsl_string('Соо("x")') == '"Соо(""x"")"'
        assert held_job._bsl_string("") == '""'

    def test_trigger_code_shape(self):
        code = held_job.build_trigger_code('Результат = 1;', "hold-abc-1", 45)
        assert 'ФоновыеЗадания.Выполнить("mcp_ОтладкаВыполненияКода.ВыполнитьКодСУдержанием", П)' in code
        assert 'П.Добавить("Результат = 1;")' in code
        assert 'П.Добавить("hold-abc-1")' in code
        assert "П.Добавить(45)" in code

    def test_trigger_code_escapes_inner_quotes(self):
        code = held_job.build_trigger_code('С = "a";', "k", 60)
        assert 'П.Добавить("С = ""a"";")' in code  # doubled quotes → valid BSL literal

    def test_multiline_code_uses_pipe_continuation(self):
        # Review 260711: multi-line code must become a valid BSL multi-line literal
        # (each continuation line starts with `|`), not break at the newline.
        s = held_job._bsl_string("А = 1;\nБ = 2;")
        assert s == '"А = 1;\n|Б = 2;"'
        # and the same via the trigger builder (CRLF normalised)
        code = held_job.build_trigger_code("X = 1;\r\nY = 2;", "k", 30)
        assert 'П.Добавить("X = 1;\n|Y = 2;")' in code

    def test_release_code_key_with_quote_escaped(self):
        assert held_job._bsl_string('k"1') == '"k""1"'

    def test_release_code_shape(self):
        rel = held_job.build_release_code("hold-abc-1")
        assert rel == 'ХранилищеОбщихНастроек.Сохранить("mcp_debug_hold_release", "hold-abc-1", Истина);'

    def test_make_key_deterministic(self):
        k1 = held_job.make_key("aaaaaaaa-bbbb", 3)
        k2 = held_job.make_key("aaaaaaaa-bbbb", 3)
        assert k1 == k2 == "hold-aaaaaaaa-3"

    def test_transport_unavailable_without_env(self, monkeypatch):
        monkeypatch.delenv("MCP_ONEC_URL", raising=False)
        assert held_job.transport_available() is False

    def test_transport_available_with_env(self, monkeypatch):
        monkeypatch.setenv("MCP_ONEC_URL", "http://localhost/transport")
        assert held_job.transport_available() is True


# --- tool integration (two-phase: no MCP_ONEC_* env) ----------------------
class _HeldClient:
    def __init__(self):
        self._attached = True
        self._registered = True
        self.session_id = "sess1234-xyz"
        self._held_job = None
        self._held_job_seq = 0
        self._line_offsets = {}
        self._http = object()  # unused in two-phase
        self.set_bp_calls = []
        self.arm_calls = 0
        self.step_calls = []
        self._stopped_targets = {"tgt"}
        self._user_visible_stops = {"tgt"}
        self._stop_reason_by_target = {"tgt": "breakpoint"}
        self._last_stopped_target_id = "tgt"

    async def set_breakpoints(self, **kw):
        self.set_bp_calls.append(kw)
        return []

    async def set_break_on_next_statement(self, silent=False):
        self.arm_calls += 1
        return True

    async def step(self, action="Continue", target_uuid=None):
        self.step_calls.append((action, target_uuid))
        return []


@pytest.fixture(autouse=True)
def _no_transport(monkeypatch):
    monkeypatch.delenv("MCP_ONEC_URL", raising=False)


@pytest.mark.asyncio
async def test_launch_two_phase_returns_trigger_and_arms(monkeypatch):
    c = _HeldClient()
    monkeypatch.setattr(mds, "_get_client", lambda: c)
    out = json.loads(
        await mds.debug_launch_held_job(
            code="Результат = 1;", timeout_sec=30, object_id="o", line=10, module_type="CommonModule"
        )
    )
    assert out["status"] == "armed"  # two-phase (no HTTP transport)
    assert out["transport"] == "two_phase"
    assert 'ВыполнитьКодСУдержанием' in out["trigger_bsl"]
    assert out["key"] == "hold-sess1234-1"
    assert out["armed_bp"]["line"] == 10  # BP armed
    assert c.arm_calls == 1  # silent break-on-next armed
    assert c._held_job is not None and c._held_job["key"] == "hold-sess1234-1"


@pytest.mark.asyncio
async def test_launch_without_bp_still_arms(monkeypatch):
    c = _HeldClient()
    monkeypatch.setattr(mds, "_get_client", lambda: c)
    out = json.loads(await mds.debug_launch_held_job(code="X = 1;", timeout_sec=60))
    assert out["armed_bp"] is None
    assert c.set_bp_calls == []  # no BP without object_id/line
    assert c.arm_calls == 1
    assert c._held_job["key"] == "hold-sess1234-1"


@pytest.mark.asyncio
async def test_step_continue_releases_held_job_two_phase(monkeypatch):
    c = _HeldClient()
    c._held_job = {"key": "hold-x-1", "timeout_sec": 60, "launched": True}
    monkeypatch.setattr(mds, "_get_client", lambda: c)
    out = json.loads(await mds.debug_step(action="Continue", target_id="tgt"))
    assert out["held_job_released"]["transport"] == "two_phase"
    assert "release_bsl" in out["held_job_released"]
    assert c._held_job is None  # cleared


@pytest.mark.asyncio
async def test_step_non_continue_does_not_release(monkeypatch):
    c = _HeldClient()
    c._held_job = {"key": "hold-x-1", "timeout_sec": 60, "launched": True}
    monkeypatch.setattr(mds, "_get_client", lambda: c)
    out = json.loads(await mds.debug_step(action="Step", target_id="tgt"))
    assert "held_job_released" not in out
    assert c._held_job is not None  # Step must not free the hold


@pytest.mark.asyncio
async def test_release_tool_no_active_job(monkeypatch):
    c = _HeldClient()
    monkeypatch.setattr(mds, "_get_client", lambda: c)
    out = json.loads(await mds.debug_release_held_job())
    assert out["released"] is False
