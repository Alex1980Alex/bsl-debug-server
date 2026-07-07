"""Unit tests for autonomy.py — A0 build_frame_bundle (roadmap 260708 §7.2).

Strategy: FakeClient with cached stack + async eval_locals_auto/get_call_stack;
uuid_index monkeypatched to isolate from real EDT export.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import autonomy
import uuid_index


OID = "11111111-2222-3333-4444-555555555555"
PID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def _frame(line=70):
    return {"moduleID": {"objectID": OID, "propertyID": PID}, "lineNo": line}


class FakeClient:
    def __init__(self, cached_stack=None, locals_result=None, pull_stack=None, locals_raises=False):
        self._last_stack_by_target = {}
        if cached_stack is not None:
            self._last_stack_by_target["tgt"] = cached_stack
        self._pull_stack = pull_stack or []
        self._locals_result = locals_result if locals_result is not None else []
        self._locals_raises = locals_raises
        self.get_call_stack_calls = 0

    async def get_call_stack(self, target_uuid=None):
        self.get_call_stack_calls += 1
        return self._pull_stack

    async def eval_locals_auto(self, target_uuid=None, stack_level=0):
        if self._locals_raises:
            raise RuntimeError("RDBG 400: вычисления только в остановленном предмете")
        return self._locals_result


# ---------------------------------------------------------------------------
# read_source_context
# ---------------------------------------------------------------------------


class TestReadSourceContext:
    def test_reads_window_and_marks_current(self, tmp_path, monkeypatch):
        src = tmp_path / "Module.bsl"
        src.write_text("\n".join(f"строка{n}" for n in range(1, 21)), encoding="utf-8")
        monkeypatch.setattr(uuid_index, "resolve_uuid", lambda o, p: src)
        ctx = autonomy.read_source_context(OID, PID, 10, radius=2)
        assert ctx["start"] == 8
        assert ctx["end"] == 12
        assert [ln["n"] for ln in ctx["lines"]] == [8, 9, 10, 11, 12]
        current = [ln for ln in ctx["lines"] if ln["current"]]
        assert len(current) == 1 and current[0]["n"] == 10
        assert current[0]["text"] == "строка10"

    def test_clamps_at_file_bounds(self, tmp_path, monkeypatch):
        src = tmp_path / "Module.bsl"
        src.write_text("a\nb\nc", encoding="utf-8")
        monkeypatch.setattr(uuid_index, "resolve_uuid", lambda o, p: src)
        ctx = autonomy.read_source_context(OID, PID, 1, radius=5)
        assert ctx["start"] == 1 and ctx["end"] == 3

    def test_returns_none_when_unresolved(self, monkeypatch):
        monkeypatch.setattr(uuid_index, "resolve_uuid", lambda o, p: None)
        assert autonomy.read_source_context(OID, PID, 5, radius=2) is None

    def test_returns_none_on_resolver_exception(self, monkeypatch):
        def boom(o, p):
            raise RuntimeError("index broken")

        monkeypatch.setattr(uuid_index, "resolve_uuid", boom)
        assert autonomy.read_source_context(OID, PID, 5) is None


# ---------------------------------------------------------------------------
# build_frame_bundle
# ---------------------------------------------------------------------------


class TestBuildFrameBundle:
    @pytest.mark.asyncio
    async def test_full_bundle(self, tmp_path, monkeypatch):
        src = tmp_path / "Module.bsl"
        src.write_text("\n".join(f"L{n}" for n in range(1, 101)), encoding="utf-8")
        monkeypatch.setattr(uuid_index, "resolve_uuid", lambda o, p: src)
        info = {"fqn": "Документ.X.МодульМенеджера", "file_path": str(src), "exists": True}
        monkeypatch.setattr(uuid_index, "get_source_info", lambda o, p: info)
        client = FakeClient(
            cached_stack=[_frame(70)],
            locals_result=[{"name": "Итог", "resultValueInfo": {"value": "Ложь"}}],
        )
        b = await autonomy.build_frame_bundle(client, "tgt", stack_level=0, context_radius=2)
        assert b["depth"] == 1
        assert b["resolved_source"] == info
        assert b["frame"]["resolved_source"] == info
        assert b["source_context"]["start"] == 68
        assert b["locals_mode"] == "auto"
        assert b["locals"][0]["name"] == "Итог"
        assert client.get_call_stack_calls == 0  # cached, no pull

    @pytest.mark.asyncio
    async def test_cache_miss_pulls_and_backfills(self, monkeypatch):
        monkeypatch.setattr(uuid_index, "resolve_uuid", lambda o, p: None)
        monkeypatch.setattr(uuid_index, "get_source_info", lambda o, p: None)
        client = FakeClient(cached_stack=None, pull_stack=[_frame(5)])
        b = await autonomy.build_frame_bundle(client, "tgt")
        assert client.get_call_stack_calls == 1
        assert client._last_stack_by_target["tgt"] == [_frame(5)]  # backfilled
        assert b["depth"] == 1

    @pytest.mark.asyncio
    async def test_stack_level_out_of_range(self, monkeypatch):
        monkeypatch.setattr(uuid_index, "get_source_info", lambda o, p: None)
        client = FakeClient(cached_stack=[_frame(1)])
        b = await autonomy.build_frame_bundle(client, "tgt", stack_level=3)
        assert "error" in b and b["depth"] == 1

    @pytest.mark.asyncio
    async def test_locals_unavailable_when_empty(self, monkeypatch):
        monkeypatch.setattr(uuid_index, "resolve_uuid", lambda o, p: None)
        monkeypatch.setattr(uuid_index, "get_source_info", lambda o, p: None)
        client = FakeClient(cached_stack=[_frame(5)], locals_result=[])
        b = await autonomy.build_frame_bundle(client, "tgt")
        assert b["locals_mode"] == "unavailable"
        assert b["source_context"] is None

    @pytest.mark.asyncio
    async def test_locals_error_degrades(self, monkeypatch):
        monkeypatch.setattr(uuid_index, "resolve_uuid", lambda o, p: None)
        monkeypatch.setattr(uuid_index, "get_source_info", lambda o, p: None)
        client = FakeClient(cached_stack=[_frame(5)], locals_raises=True)
        b = await autonomy.build_frame_bundle(client, "tgt")
        assert b["locals_mode"] == "error"
        assert b["locals"] == []
        assert b["depth"] == 1  # bundle still returned

    @pytest.mark.asyncio
    async def test_empty_stack_out_of_range(self, monkeypatch):
        monkeypatch.setattr(uuid_index, "get_source_info", lambda o, p: None)
        client = FakeClient(cached_stack=None, pull_stack=[])
        b = await autonomy.build_frame_bundle(client, "tgt")
        assert "error" in b and b["depth"] == 0
