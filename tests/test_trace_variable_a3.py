"""Unit tests for A3 — debug_trace_variable timeline (roadmap 260708 §7.6).

Covers:
- autonomy.find_method_range / find_assignment_lines / _extract_upstream /
  build_trace_template / read_trace_timeline (pure)
- _clear_logpoint_keys (cache + _logpoints removal)
- debug_trace_variable tool: arm (finds assignments, sets logpoints) / collect
  (reads timeline, clears) / errors

Strategy: pure funcs on sample BSL; tool with real RDBGClient + mocked _post /
set_breakpoints / uuid_index. Mirrors test_root_cause_a2 / test_heartbeat_b4.
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
from mcp_debug_server import RDBGClient, _clear_logpoint_keys

SRC = """Процедура СформироватьИтог()
    Итог = 0;
    Если Итог = 5 Тогда
        Возврат;
    КонецЕсли;
    Для Каждого Строка Из Таблица Цикл
        Итог = Итог + Строка.Сумма * Ставка;
    КонецЦикла;
    Результат.Итог = Итог;
КонецПроцедуры

Функция Другая()
    Итог = 999;
КонецФункции
""".splitlines()


def _make_client() -> RDBGClient:
    c = RDBGClient(debug_url="http://localhost:1550", infobase_alias="TestDB")
    c._post = AsyncMock(return_value=ET.Element("empty"))
    return c


# ---------------------------------------------------------------------------
# find_method_range
# ---------------------------------------------------------------------------


class TestMethodRange:
    def test_finds_procedure(self):
        assert autonomy.find_method_range(SRC, "СформироватьИтог") == (1, 10)

    def test_finds_function(self):
        assert autonomy.find_method_range(SRC, "Другая") == (12, 14)

    def test_not_found(self):
        assert autonomy.find_method_range(SRC, "НетТакого") is None

    def test_empty_name(self):
        assert autonomy.find_method_range(SRC, "") is None


# ---------------------------------------------------------------------------
# find_assignment_lines
# ---------------------------------------------------------------------------


class TestAssignmentLines:
    def test_whole_module_finds_all_assignments(self):
        res = autonomy.find_assignment_lines(SRC, "Итог")
        lines = [r["line"] for r in res]
        # assignments: L2 (Итог=0), L7 (Итог=Итог+...), L13 (Итог=999).
        # NOT L3 (Если Итог = 5 — comparison), NOT L9 (Результат.Итог = — member).
        assert lines == [2, 7, 13]

    def test_scoped_to_method(self):
        rng = autonomy.find_method_range(SRC, "СформироватьИтог")
        res = autonomy.find_assignment_lines(SRC, "Итог", rng)
        assert [r["line"] for r in res] == [2, 7]  # L13 excluded (other method)

    def test_excludes_comparison_and_member(self):
        res = autonomy.find_assignment_lines(SRC, "Итог")
        assert 3 not in [r["line"] for r in res]  # Если Итог = 5
        assert 9 not in [r["line"] for r in res]  # Результат.Итог =

    def test_upstream_extracted(self):
        res = autonomy.find_assignment_lines(SRC, "Итог")
        l7 = next(r for r in res if r["line"] == 7)
        # RHS "Итог + Строка.Сумма * Ставка" → upstream excludes Итог (self) and
        # the member tail Сумма; keeps the objects Строка / Ставка.
        assert "Итог" not in l7["upstream"]
        assert "Строка" in l7["upstream"] and "Ставка" in l7["upstream"]

    def test_empty_name(self):
        assert autonomy.find_assignment_lines(SRC, "") == []


class TestExtractUpstream:
    def test_filters_keywords_and_self(self):
        up = autonomy._extract_upstream("Итог + Строка Из Массив", "Итог")
        assert "Итог" not in up
        assert "Из" not in up  # keyword
        assert "Строка" in up and "Массив" in up

    def test_skips_call_heads(self):
        up = autonomy._extract_upstream("ВычислитьСумму(Х) + Ставка", "Итог")
        assert "ВычислитьСумму" not in up  # followed by ( → call, not var
        assert "Ставка" in up

    def test_cap(self):
        up = autonomy._extract_upstream("А + Б + В + Г + Д", "Итог", cap=2)
        assert len(up) == 2


class TestBuildTemplate:
    def test_name_only(self):
        assert autonomy.build_trace_template("Итог", []) == "Итог={Итог}"

    def test_with_upstream(self):
        assert autonomy.build_trace_template("Итог", ["Сумма", "Ставка"]) == (
            "Итог={Итог} Сумма={Сумма} Ставка={Ставка}"
        )


# ---------------------------------------------------------------------------
# read_trace_timeline
# ---------------------------------------------------------------------------


class TestReadTimeline:
    def _write(self, tmp_path, sid, entries):
        p = tmp_path / f"{sid}.jsonl"
        p.write_text("\n".join(json.dumps(e, ensure_ascii=False) for e in entries) + "\n", encoding="utf-8")
        return p

    def test_filters_by_keys_and_extracts_value(self, tmp_path):
        entries = [
            {"object_id": "o", "property_id": "p", "line": 2, "ts": "t1", "evaluated": {"Итог": "0"}, "rendered": "Итог=0"},
            {"object_id": "o", "property_id": "p", "line": 8, "ts": "t2", "evaluated": {"Итог": "42"}, "rendered": "Итог=42"},
            {"object_id": "other", "property_id": "p", "line": 9, "ts": "t3", "evaluated": {"X": "1"}},  # not in keys
        ]
        self._write(tmp_path, "sid", entries)
        keys = {("o", "p", 2), ("o", "p", 8)}
        tl = autonomy.read_trace_timeline(tmp_path, "sid", keys, 0, "Итог")
        assert [t["value"] for t in tl] == ["0", "42"]
        assert [t["line"] for t in tl] == [2, 8]

    def test_skips_lines_predating_arm(self, tmp_path):
        entries = [
            {"object_id": "o", "property_id": "p", "line": 2, "ts": "old", "evaluated": {"Итог": "PRE"}},
            {"object_id": "o", "property_id": "p", "line": 2, "ts": "new", "evaluated": {"Итог": "POST"}},
        ]
        self._write(tmp_path, "sid", entries)
        tl = autonomy.read_trace_timeline(tmp_path, "sid", {("o", "p", 2)}, 1, "Итог")
        assert [t["value"] for t in tl] == ["POST"]

    def test_missing_file_returns_empty(self, tmp_path):
        assert autonomy.read_trace_timeline(tmp_path, "nope", {("o", "p", 2)}, 0, "Итог") == []


# ---------------------------------------------------------------------------
# _clear_logpoint_keys
# ---------------------------------------------------------------------------


class TestClearLogpointKeys:
    def test_removes_from_logpoints_and_cache(self):
        c = _make_client()
        c._logpoints = {("o", "p", 2): "t", ("o", "p", 8): "t", ("o", "p", 99): "keep"}
        c._set_breakpoints_cache = [
            {"object_id": "o", "property_id": "p", "lines": [2, 8, 99], "module_type": "ConfigModule"}
        ]
        removed = _clear_logpoint_keys(c, {("o", "p", 2), ("o", "p", 8)})
        assert removed == 2
        assert ("o", "p", 2) not in c._logpoints and ("o", "p", 99) in c._logpoints
        assert c._set_breakpoints_cache[0]["lines"] == [99]  # kept the untouched line

    def test_drops_empty_cache_entry(self):
        c = _make_client()
        c._logpoints = {("o", "p", 2): "t"}
        c._set_breakpoints_cache = [
            {"object_id": "o", "property_id": "p", "lines": [2], "module_type": "ConfigModule"}
        ]
        _clear_logpoint_keys(c, {("o", "p", 2)})
        assert c._set_breakpoints_cache == []  # entry removed when no lines left


# ---------------------------------------------------------------------------
# debug_trace_variable tool
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestDebugTraceVariable:
    async def test_not_connected(self, monkeypatch):
        c = _make_client()
        c._attached = False
        monkeypatch.setattr(mds, "_get_client", lambda: c)
        out = json.loads(await mds.debug_trace_variable(name="Итог", object_id="o", phase="arm"))
        assert out["error_type"] == "not_connected"

    async def test_bad_phase(self, monkeypatch):
        c = _make_client()
        c._attached = c._registered = True
        monkeypatch.setattr(mds, "_get_client", lambda: c)
        out = json.loads(await mds.debug_trace_variable(name="Итог", phase="bogus"))
        assert out["error_type"] == "bad_phase"

    async def test_arm_sets_logpoints(self, tmp_path, monkeypatch):
        src = tmp_path / "Module.bsl"
        src.write_text("\n".join(SRC), encoding="utf-8")
        c = _make_client()
        c._attached = c._registered = True
        c._log_dir = tmp_path
        c.set_breakpoints = AsyncMock()
        c.set_break_on_next_statement = AsyncMock()
        monkeypatch.setattr(mds, "_get_client", lambda: c)
        monkeypatch.setattr(mds.uuid_index, "resolve_uuid", lambda o, p: str(src))
        out = json.loads(
            await mds.debug_trace_variable(
                name="Итог", object_id="o", phase="arm", method="СформироватьИтог"
            )
        )
        assert out["status"] == "armed"
        assert [ln["src_line"] for ln in out["lines"]] == [2, 7]
        assert c.set_breakpoints.await_count >= 1
        c.set_break_on_next_statement.assert_awaited_once()
        assert c._trace_var is not None and c._trace_var["name"] == "Итог"

    async def test_arm_method_not_found(self, tmp_path, monkeypatch):
        src = tmp_path / "Module.bsl"
        src.write_text("\n".join(SRC), encoding="utf-8")
        c = _make_client()
        c._attached = c._registered = True
        monkeypatch.setattr(mds, "_get_client", lambda: c)
        monkeypatch.setattr(mds.uuid_index, "resolve_uuid", lambda o, p: str(src))
        out = json.loads(
            await mds.debug_trace_variable(name="Итог", object_id="o", phase="arm", method="Нет")
        )
        assert out["error_type"] == "method_not_found"

    async def test_arm_no_assignments(self, tmp_path, monkeypatch):
        src = tmp_path / "Module.bsl"
        src.write_text("\n".join(SRC), encoding="utf-8")
        c = _make_client()
        c._attached = c._registered = True
        c._log_dir = tmp_path
        c.set_breakpoints = AsyncMock()
        c.set_break_on_next_statement = AsyncMock()
        monkeypatch.setattr(mds, "_get_client", lambda: c)
        monkeypatch.setattr(mds.uuid_index, "resolve_uuid", lambda o, p: str(src))
        out = json.loads(
            await mds.debug_trace_variable(name="НетТакойПеременной", object_id="o", phase="arm")
        )
        assert out["status"] == "no_assignments"

    async def test_arm_clears_prior_trace(self, tmp_path, monkeypatch):
        # Hardening: re-arm without collect must clear the previous trace's
        # logpoints (else they linger + fire silently).
        src = tmp_path / "Module.bsl"
        src.write_text("\n".join(SRC), encoding="utf-8")
        c = _make_client()
        c._attached = c._registered = True
        c._log_dir = tmp_path
        c.set_breakpoints = AsyncMock()
        c.set_break_on_next_statement = AsyncMock()
        c._push_bp_workspace = AsyncMock()
        # prior trace present
        c._trace_var = {"name": "Старая", "keys": {("o", "p", 99)}, "armed_log_lines": 0}
        c._logpoints = {("o", "p", 99): "old"}
        monkeypatch.setattr(mds, "_get_client", lambda: c)
        monkeypatch.setattr(mds.uuid_index, "resolve_uuid", lambda o, p: str(src))
        out = json.loads(
            await mds.debug_trace_variable(name="Итог", object_id="o", phase="arm")
        )
        assert out["status"] == "armed"
        assert ("o", "p", 99) not in c._logpoints  # prior trace cleared
        c._push_bp_workspace.assert_awaited()  # RDBG workspace re-pushed
        assert c._trace_var["name"] == "Итог"  # new trace armed

    async def test_collect_no_trace(self, monkeypatch):
        c = _make_client()
        c._attached = c._registered = True
        c._trace_var = None
        monkeypatch.setattr(mds, "_get_client", lambda: c)
        out = json.loads(await mds.debug_trace_variable(name="Итог", phase="collect"))
        assert out["error_type"] == "no_trace"

    async def test_collect_reads_timeline_and_clears(self, tmp_path, monkeypatch):
        c = _make_client()
        c._attached = c._registered = True
        c._log_dir = tmp_path
        keys = {("o", "p", 2), ("o", "p", 8)}
        c._trace_var = {"name": "Итог", "keys": keys, "armed_log_lines": 0}
        c._logpoints = {("o", "p", 2): "t", ("o", "p", 8): "t"}
        c._set_breakpoints_cache = [
            {"object_id": "o", "property_id": "p", "lines": [2, 8], "module_type": "ConfigModule"}
        ]
        c._push_bp_workspace = AsyncMock()
        entries = [
            {"object_id": "o", "property_id": "p", "line": 2, "ts": "t1", "evaluated": {"Итог": "0"}, "rendered": "Итог=0"},
            {"object_id": "o", "property_id": "p", "line": 8, "ts": "t2", "evaluated": {"Итог": "42"}, "rendered": "Итог=42"},
        ]
        (tmp_path / f"{c.session_id}.jsonl").write_text(
            "\n".join(json.dumps(e, ensure_ascii=False) for e in entries) + "\n", encoding="utf-8"
        )
        monkeypatch.setattr(mds, "_get_client", lambda: c)
        out = json.loads(await mds.debug_trace_variable(name="Итог", phase="collect"))
        assert out["hits"] == 2
        assert [t["value"] for t in out["timeline"]] == ["0", "42"]
        assert out["lines_traced"] == [2, 8]
        assert c._trace_var is None  # reset
        c._push_bp_workspace.assert_awaited_once()
        assert ("o", "p", 2) not in c._logpoints  # logpoints cleared
