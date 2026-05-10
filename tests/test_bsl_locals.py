"""Unit tests for bsl_locals.extract_locals_at_line."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from bsl_locals import extract_locals_at_line


def _write_bsl(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "test.bsl"
    p.write_text(content, encoding="utf-8")
    return p


class TestParameterExtraction:
    def test_simple_params(self, tmp_path):
        src = """
Процедура ТестМетод(ПервыйПарам, ВторойПарам)
    А = 1;
КонецПроцедуры
"""
        path = _write_bsl(tmp_path, src)
        # Line 3 — inside body, both params visible
        assert extract_locals_at_line(path, 3)[:2] == ["ПервыйПарам", "ВторойПарам"]

    def test_params_with_defaults(self, tmp_path):
        src = """
Процедура ТестМетод(А = 5, Б = "строка", В)
КонецПроцедуры
"""
        path = _write_bsl(tmp_path, src)
        names = extract_locals_at_line(path, 2)
        assert "А" in names and "Б" in names and "В" in names

    def test_params_with_znach_modifier(self, tmp_path):
        src = """
Функция Считать(Знач Имя, Знач Путь = "")
    Возврат "X";
КонецФункции
"""
        path = _write_bsl(tmp_path, src)
        names = extract_locals_at_line(path, 2)
        assert names[:2] == ["Имя", "Путь"]

    def test_no_function_returns_empty(self, tmp_path):
        src = "// just a comment\n#Область Foo\n#КонецОбласти\n"
        path = _write_bsl(tmp_path, src)
        assert extract_locals_at_line(path, 1) == []

    def test_english_keywords(self, tmp_path):
        src = """
Procedure DoIt(First, Val Second = 0)
    X = 1;
EndProcedure
"""
        path = _write_bsl(tmp_path, src)
        names = extract_locals_at_line(path, 3)
        assert "First" in names
        assert "Second" in names


class TestLocalVarExtraction:
    def test_local_var_declaration(self, tmp_path):
        src = """
Процедура М()
    Перем Локальная1, Локальная2;
    Локальная1 = 5;
КонецПроцедуры
"""
        path = _write_bsl(tmp_path, src)
        names = extract_locals_at_line(path, 3)
        assert "Локальная1" in names and "Локальная2" in names

    def test_var_declared_after_target_still_visible(self, tmp_path):
        # BSL hoists Перем — variable declared AFTER current line is still visible
        src = """
Процедура М()
    А = 1;
    Перем ОбъявленаПозже;
КонецПроцедуры
"""
        path = _write_bsl(tmp_path, src)
        names = extract_locals_at_line(path, 3)
        assert "ОбъявленаПозже" in names


class TestAssignmentExtraction:
    def test_first_assignment_creates_local(self, tmp_path):
        src = """
Процедура М()
    НоваяПерем = 100;
    НоваяПерем = 200;
КонецПроцедуры
"""
        path = _write_bsl(tmp_path, src)
        names = extract_locals_at_line(path, 4)
        assert "НоваяПерем" in names

    def test_assignment_after_target_NOT_in_scope(self, tmp_path):
        # Assignment after target_line — variable not yet bound
        src = """
Процедура М()
    А = 1;
    БудущаяПерем = 99;
КонецПроцедуры
"""
        path = _write_bsl(tmp_path, src)
        names = extract_locals_at_line(path, 3)
        assert "А" in names
        assert "БудущаяПерем" not in names

    def test_property_assignment_excluded(self, tmp_path):
        # X.Y = ... is property assignment, not a local declaration
        src = """
Процедура М()
    Объект.Поле = 5;
КонецПроцедуры
"""
        path = _write_bsl(tmp_path, src)
        names = extract_locals_at_line(path, 3)
        assert "Объект" not in names
        assert "Поле" not in names

    def test_for_loop_variable(self, tmp_path):
        src = """
Процедура М()
    Для Сч = 1 По 10 Цикл
        Итог = Сч * 2;
    КонецЦикла;
КонецПроцедуры
"""
        path = _write_bsl(tmp_path, src)
        names = extract_locals_at_line(path, 4)
        assert "Сч" in names
        assert "Итог" in names

    def test_for_each_variable(self, tmp_path):
        src = """
Процедура М()
    Для Каждого Элемент Из Коллекция Цикл
        Имя = Элемент.Имя;
    КонецЦикла;
КонецПроцедуры
"""
        path = _write_bsl(tmp_path, src)
        names = extract_locals_at_line(path, 4)
        assert "Элемент" in names
        assert "Имя" in names


class TestModuleVarExtraction:
    def test_module_var_visible_in_function(self, tmp_path):
        src = """
Перем МоднаяПерем Экспорт;
Перем ВтораяМоднаяПерем;

Процедура М()
    А = МоднаяПерем;
КонецПроцедуры
"""
        path = _write_bsl(tmp_path, src)
        names = extract_locals_at_line(path, 6)
        assert "МоднаяПерем" in names
        assert "ВтораяМоднаяПерем" in names
        assert "А" in names

    def test_module_var_with_no_function(self, tmp_path):
        # Module-only file (rare, but valid)
        src = """
Перем Глобальная;
"""
        path = _write_bsl(tmp_path, src)
        names = extract_locals_at_line(path, 2)
        assert names == ["Глобальная"]


class TestFunctionBoundary:
    def test_locals_isolated_per_function(self, tmp_path):
        src = """
Процедура М1(ПарамМ1)
    ЛокМ1 = 1;
КонецПроцедуры

Процедура М2(ПарамМ2)
    ЛокМ2 = 2;
КонецПроцедуры
"""
        path = _write_bsl(tmp_path, src)
        # Inside М1
        names_m1 = extract_locals_at_line(path, 3)
        assert "ПарамМ1" in names_m1 and "ЛокМ1" in names_m1
        assert "ПарамМ2" not in names_m1 and "ЛокМ2" not in names_m1
        # Inside М2
        names_m2 = extract_locals_at_line(path, 7)
        assert "ПарамМ2" in names_m2 and "ЛокМ2" in names_m2
        assert "ПарамМ1" not in names_m2 and "ЛокМ1" not in names_m2


class TestEdgeCases:
    def test_unreadable_file_returns_empty(self, tmp_path):
        nonexistent = tmp_path / "no.bsl"
        assert extract_locals_at_line(nonexistent, 1) == []

    def test_dedupes_case_insensitively(self, tmp_path):
        # BSL identifiers case-insensitive — same name in two cases = one entry
        src = """
Процедура М()
    Перем имя;
    Имя = 5;
    ИМЯ = 10;
КонецПроцедуры
"""
        path = _write_bsl(tmp_path, src)
        names = extract_locals_at_line(path, 5)
        # First-seen case wins; only one entry for the name
        lowered = [n.lower() for n in names]
        assert lowered.count("имя") == 1
