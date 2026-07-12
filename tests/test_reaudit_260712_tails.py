"""Re-audit 260712 tails: en-fqn reverse resolve, duplicate-method warning,
F-4 (watch-halt visible in session metrics), F-5 (_watch_last per-target).
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import autonomy
import uuid_index as ui
import watchpoints


# --- en-fqn reverse resolve ---------------------------------------------------
class TestEnFqn:
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

    def test_common_module_en(self):
        rev = ui._reverse_fqn_entries(self._entries())
        assert rev["commonmodule.мсп_служебный"] == ("aaaa", "CommonModule")

    def test_document_object_manager_recordset_en(self):
        rev = ui._reverse_fqn_entries(self._entries())
        assert rev["document.реализация.objectmodule"] == ("bbbb", "ObjectModule")
        assert rev["document.реализация.managermodule"] == ("bbbb", "ManagerModule")
        assert rev["informationregister.цены.recordsetmodule"] == ("rrrr", "RecordSetModule")

    def test_form_module_en(self):
        rev = ui._reverse_fqn_entries(self._entries())
        assert rev["document.реализация.form.формадокумента"] == ("ffff", "FormModule")

    def test_ru_still_works(self):
        # EN keys are additive — RU resolution unchanged (regression guard)
        rev = ui._reverse_fqn_entries(self._entries())
        assert rev["общиймодуль.мсп_служебный"] == ("aaaa", "CommonModule")
        assert rev["документ.реализация.модульобъекта"] == ("bbbb", "ObjectModule")


# --- duplicate method definitions -------------------------------------------
class TestCountMethodDefs:
    def test_single(self):
        src = ["Процедура Тест()", "    Возврат;", "КонецПроцедуры"]
        assert autonomy.count_method_definitions(src, "Тест") == 1

    def test_duplicate(self):
        src = [
            "Процедура Дубль()", "КонецПроцедуры",
            "Функция Дубль(А)", "    Возврат А;", "КонецФункции",
        ]
        assert autonomy.count_method_definitions(src, "Дубль") == 2

    def test_absent(self):
        assert autonomy.count_method_definitions(["Процедура Иной()"], "Нет") == 0

    def test_range_takes_first(self):
        src = [
            "Процедура Дубль()", "    А = 1;", "КонецПроцедуры",
            "Процедура Дубль()", "    Б = 2;", "КонецПроцедуры",
        ]
        assert autonomy.find_method_range(src, "Дубль") == (1, 3)  # first definition


# --- F-4 / F-5: watch-halt metrics + per-target change detection -------------
class _MockClient:
    def __init__(self, eval_value, mode="break_on_first_change"):
        self.session_id = "sess"
        self._watch_last = {}
        self._watch_changes = []
        self._user_visible_stops = set()
        self._stop_events = []
        self._rphosts_seen = set()
        self._watch_halt_count = 0
        self._last_visible_stop_ts = 0.0
        self._signalled = 0
        self._eval_value = eval_value
        self.step = AsyncMock()
        key = ("o", "p", 2)
        self._watchpoints = {
            key: {"name": "Ответ", "mode": mode, "predicate": None, "run_id": "r1",
                  "fires": 0, "max_fires": 200}
        }

    async def eval_expression(self, expression, target_uuid, stack_level=0):
        return self._eval_value

    def _signal_bp_stop(self):
        self._signalled += 1


def _stack():
    return [{"moduleID": {"objectID": "o", "propertyID": "p"}, "lineNo": 2}]


@pytest.mark.asyncio
async def test_f4_watch_halt_recorded_in_metrics(tmp_path):
    c = _MockClient("2")
    c._watch_last[("t1", "Ответ")] = "1"  # prior value → change to "2" → halt
    await watchpoints.fire_watchpoint(c, "t1", _stack(), tmp_path)
    await watchpoints.drain_active()
    c.step.assert_not_awaited()  # halted
    assert c._watch_halt_count == 1
    assert c._stop_events[-1]["reason"] == "watchpoint"
    assert c._stop_events[-1]["lineNo"] == 2
    assert "t1" in c._rphosts_seen


@pytest.mark.asyncio
async def test_f5_watch_last_per_target(tmp_path):
    # Same name on two targets must not interleave: t1 sees 1→1 (no change),
    # t2 sees its own first observation (old=None).
    c = _MockClient("1", mode="record_only")
    c._watch_last[("t1", "Ответ")] = "1"  # t1 already saw "1"
    await watchpoints.fire_watchpoint(c, "t1", _stack(), tmp_path)
    await watchpoints.drain_active()
    # t1 unchanged → no record
    assert c._watch_changes == []
    # t2 first observation → recorded with old=None
    await watchpoints.fire_watchpoint(c, "t2", _stack(), tmp_path)
    await watchpoints.drain_active()
    assert len(c._watch_changes) == 1
    assert c._watch_changes[0]["old"] is None
    assert c._watch_last[("t1", "Ответ")] == "1"
    assert c._watch_last[("t2", "Ответ")] == "1"
