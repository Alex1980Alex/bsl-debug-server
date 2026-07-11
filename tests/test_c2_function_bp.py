"""C2 (roadmap 260708 §8.2) unit tests: Function BP by method name.

Covers uuid_index._reverse_fqn_entries (fqn -> (object_id, module_type),
mirrors get_source_info), _first_executable_line, and the
debug_set_function_breakpoint tool (bad_fqn / module_not_found /
method_not_found / success with first-executable relocation).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import uuid_index as ui
import mcp_debug_server as mds


# --- reverse fqn map (pure) ----------------------------------------------
class TestReverseFqn:
    def _entries(self):
        return {
            "aaaa": {"mdo": "CommonModules/мсп_Служебный/мсп_Служебный.mdo",
                     "name": "мсп_Служебный", "kind": "commonmodule", "child_kind": None},
            "bbbb": {"mdo": "Documents/Реализация/Реализация.mdo",
                     "name": "Реализация", "kind": "document", "child_kind": None},
            "ffff": {"mdo": "Documents/Реализация/Реализация.mdo",
                     "name": "ФормаДокумента", "kind": "document", "child_kind": "forms"},
            "rrrr": {"mdo": "InformationRegisters/Цены/Цены.mdo",
                     "name": "Цены", "kind": "informationregister", "child_kind": None},
        }

    def test_register_recordset_and_manager(self):
        # reverse map generates the RecordSet + Manager combos for a register
        # (whether resolve() then finds the right .bsl is a separate resolve()
        # concern — see roadmap §8.2 follow-up on MODULE_PROPERTY_FILES).
        rev = ui._reverse_fqn_entries(self._entries())
        assert rev["регистрсведений.цены.модульнаборазаписей"] == ("rrrr", "RecordSetModule")
        assert rev["регистрсведений.цены.модульменеджера"] == ("rrrr", "ManagerModule")

    def test_common_module_fqn(self):
        rev = ui._reverse_fqn_entries(self._entries())
        assert rev["общиймодуль.мсп_служебный".lower()] == ("aaaa", "CommonModule")

    def test_document_object_and_manager(self):
        rev = ui._reverse_fqn_entries(self._entries())
        assert rev["документ.реализация.модульобъекта"] == ("bbbb", "ObjectModule")
        assert rev["документ.реализация.модульменеджера"] == ("bbbb", "ManagerModule")

    def test_form_module_fqn(self):
        rev = ui._reverse_fqn_entries(self._entries())
        # parent dir of the mdo is "Реализация"; form name "ФормаДокумента"
        assert rev["документ.реализация.форма.формадокумента"] == ("ffff", "FormModule")

    def test_unknown_fqn_absent(self):
        rev = ui._reverse_fqn_entries(self._entries())
        assert "документ.несуществует.модульобъекта" not in rev


# --- _first_executable_line ----------------------------------------------
class TestFirstExecutableLine:
    def test_skips_header_and_comment(self):
        src = [
            "Процедура Тест()",      # 1 header
            "    // коммент",          # 2 comment
            "    Перем Х;",            # 3 declaration
            "    Х = 1;",              # 4 executable  <-- first
            "КонецПроцедуры",          # 5 structural
        ]
        assert mds._first_executable_line(src, 1, 5) == 4

    def test_none_when_no_executable(self):
        src = ["Процедура П()", "КонецПроцедуры"]
        assert mds._first_executable_line(src, 1, 2) is None


# --- debug_set_function_breakpoint tool ----------------------------------
class _Client:
    _attached = True
    _registered = True


@pytest.fixture
def _client(monkeypatch):
    c = _Client()
    monkeypatch.setattr(mds, "_get_client", lambda: c)
    return c


@pytest.mark.asyncio
async def test_bad_fqn_no_dot(_client):
    out = json.loads(await mds.debug_set_function_breakpoint("NoDot"))
    assert out["error_type"] == "bad_fqn"


@pytest.mark.asyncio
async def test_module_not_found(_client, monkeypatch):
    monkeypatch.setattr(mds.uuid_index, "find_by_fqn", lambda fqn: None)
    out = json.loads(
        await mds.debug_set_function_breakpoint("ОбщийМодуль.Нет.Метод")
    )
    assert out["error_type"] == "module_not_found"


@pytest.mark.asyncio
async def test_method_not_found(_client, monkeypatch, tmp_path):
    f = tmp_path / "Module.bsl"
    f.write_text("Процедура Другой()\n    Х = 1;\nКонецПроцедуры\n", encoding="utf-8-sig")
    monkeypatch.setattr(mds.uuid_index, "find_by_fqn", lambda fqn: ("oid", "CommonModule"))
    monkeypatch.setattr(mds.uuid_index, "resolve_uuid", lambda oid, pid: str(f))
    out = json.loads(
        await mds.debug_set_function_breakpoint("ОбщийМодуль.М.НетТакого")
    )
    assert out["error_type"] == "method_not_found"


@pytest.mark.asyncio
async def test_success_relocates_to_first_executable(_client, monkeypatch, tmp_path):
    f = tmp_path / "Module.bsl"
    f.write_text(
        "Процедура ВыполнитьКод(Код)\n    // do\n    Х = 1;\nКонецПроцедуры\n",
        encoding="utf-8-sig",
    )
    monkeypatch.setattr(mds.uuid_index, "find_by_fqn", lambda fqn: ("oid", "CommonModule"))
    monkeypatch.setattr(mds.uuid_index, "resolve_uuid", lambda oid, pid: str(f))
    monkeypatch.setattr(
        mds, "debug_set_breakpoint",
        AsyncMock(return_value='{"status": "breakpoint_set", "line": 3}'),
    )
    out = json.loads(
        await mds.debug_set_function_breakpoint("ОбщийМодуль.М.ВыполнитьКод")
    )
    assert out["resolved"]["method"] == "ВыполнитьКод"
    assert out["resolved"]["module_type"] == "CommonModule"
    # header line 1, comment 2 -> first executable is line 3 (Х = 1;)
    assert out["resolved"]["line"] == 3
    assert out["resolved"]["method_range"] == [1, 4]
    assert out["bp"]["status"] == "breakpoint_set"
    # debug_set_breakpoint called with the relocated line
    assert mds.debug_set_breakpoint.await_args.kwargs["line"] == 3
