"""C3 (roadmap 260708 §8.1) unit tests: BSL line-executability classifier.

Covers classify_line (all 9 classes + edge cases), classify_lines (range
clamping, empty, text field) and nearest_executable (self, forward tie-break,
none). The heuristic is refined live by the coverage-fan (C3.6); these pin the
static behavior so a regression is caught without a live base.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import bsl_locals as bl


class TestClassifyLine:
    def test_blank(self):
        assert bl.classify_line("") == ("blank", False)
        assert bl.classify_line("   \t ") == ("blank", False)

    def test_comment(self):
        assert bl.classify_line("// коммент") == ("comment", False)
        assert bl.classify_line("    // indented") == ("comment", False)

    def test_string_continuation(self):
        assert bl.classify_line("|   Товар") == ("string_continuation", False)
        assert bl.classify_line('|ИЗ Справочник.Товары";') == ("string_continuation", False)

    def test_preprocessor(self):
        assert bl.classify_line("#Если Сервер Тогда") == ("preprocessor", False)
        assert bl.classify_line("#Область Служебные") == ("preprocessor", False)
        assert bl.classify_line("#КонецОбласти") == ("preprocessor", False)

    def test_directive(self):
        assert bl.classify_line("&НаСервереБезКонтекста") == ("directive", False)
        assert bl.classify_line("&AtClient") == ("directive", False)

    def test_declaration(self):
        assert bl.classify_line("Перем СуммаИтога;") == ("declaration", False)
        assert bl.classify_line("    Var X, Y;") == ("declaration", False)

    def test_header_is_uncertain(self):
        assert bl.classify_line("Процедура ОбработкаПроведения(Отказ)") == ("header", True)
        assert bl.classify_line("Функция мсп_Прочитать(Ключ) Экспорт") == ("header", True)
        assert bl.classify_line("Function Compute()") == ("header", True)

    def test_structural_is_uncertain(self):
        for kw in ("КонецЕсли", "КонецЦикла", "КонецПопытки", "КонецПроцедуры",
                   "КонецФункции", "Иначе", "Попытка", "Исключение",
                   "EndIf", "EndDo", "Else", "Try", "Except"):
            cls, unc = bl.classify_line("    " + kw)
            assert cls == "structural", f"{kw} -> {cls}"
            assert unc is True
        # trailing `;` and comment tolerated
        assert bl.classify_line("КонецЕсли; // done") == ("structural", True)

    def test_executable_assignment(self):
        assert bl.classify_line("СуммаИтога = 0;") == ("executable", False)
        assert bl.classify_line("    Ответ = 40 + 2;") == ("executable", False)

    def test_executable_conditions_and_flow(self):
        # `Иначе` is structural but `ИначеЕсли <cond> Тогда` evaluates -> executable
        assert bl.classify_line("ИначеЕсли Х > 0 Тогда") == ("executable", False)
        assert bl.classify_line("Если Заполнено Тогда") == ("executable", False)
        assert bl.classify_line("Пока НЕ Конец Цикл") == ("executable", False)
        assert bl.classify_line("Для Каждого Стр Из Таблица Цикл") == ("executable", False)
        assert bl.classify_line("Возврат Истина;") == ("executable", False)

    def test_executable_single_line_block(self):
        # single-line `Если X Тогда Y; КонецЕсли;` — whole line is executable,
        # NOT structural (the trailing КонецЕсли doesn't make the line non-code)
        assert bl.classify_line("Если Х Тогда Прервать; КонецЕсли;") == ("executable", False)

    def test_executable_cyrillic_prefix_ident(self):
        assert bl.classify_line("гкс_Служебный.Метод();") == ("executable", False)


class TestClassifyLines:
    def test_range_and_text(self):
        src = ["Процедура П()", "    // c", "    X = 1;", "КонецПроцедуры"]
        out = bl.classify_lines(src, 1, 4)
        assert out[1]["class"] == "header" and out[1]["uncertain"] is True
        assert out[2]["class"] == "comment" and out[2]["executable"] is False
        assert out[3]["class"] == "executable" and out[3]["executable"] is True
        assert out[3]["text"] == "X = 1;"  # stripped
        assert out[4]["class"] == "structural"

    def test_bounds_clamped(self):
        src = ["A = 1;", "B = 2;"]
        out = bl.classify_lines(src, 0, 99)  # clamped to [1,2]
        assert set(out) == {1, 2}

    def test_partial_range(self):
        src = ["A = 1;", "B = 2;", "C = 3;"]
        out = bl.classify_lines(src, 2, 2)
        assert set(out) == {2}

    def test_empty_source(self):
        assert bl.classify_lines([], 1, 10) == {}


class TestNearestExecutable:
    def test_self_when_executable(self):
        src = ["A = 1;", "B = 2;"]
        c = bl.classify_lines(src)
        assert bl.nearest_executable(c, 1) == 1

    def test_forward_on_comment(self):
        # target is a comment; nearest executable is the line after
        src = ["// header comment", "X = 1;"]
        c = bl.classify_lines(src)
        assert bl.nearest_executable(c, 1) == 2

    def test_tie_prefers_forward(self):
        # line 2 is blank; lines 1 and 3 both executable, distance 1 each ->
        # forward (3) wins
        src = ["A = 1;", "", "B = 2;"]
        c = bl.classify_lines(src)
        assert bl.nearest_executable(c, 2) == 3

    def test_none_when_no_executable(self):
        src = ["// only", "КонецЕсли", ""]
        c = bl.classify_lines(src)
        assert bl.nearest_executable(c, 1) is None

    def test_backward_when_only_before(self):
        src = ["A = 1;", "// tail", "КонецПроцедуры"]
        c = bl.classify_lines(src)
        assert bl.nearest_executable(c, 3) == 1


class TestClassifyBpLineBOM:
    """Regression (code-verify 2026-07-11): 1С EDT/Designer .bsl dumps carry a
    BOM; the file reader must use utf-8-sig, else `﻿` sticks to line 1 and
    str.strip() won't remove it → line-1 prefix matches fail → misclassified."""

    def test_bom_file_line1_header_not_executable(self, tmp_path, monkeypatch):
        import mcp_debug_server as mds

        f = tmp_path / "Module.bsl"
        f.write_text("Процедура П()\n    X = 1;\nКонецПроцедуры\n", encoding="utf-8-sig")
        monkeypatch.setattr(mds, "_resolve_property_id", lambda mt, pid: ("ConfigModule", "pid"))
        monkeypatch.setattr(mds.uuid_index, "resolve_uuid", lambda oid, pid: str(f))

        out = mds._classify_bp_line("oid", "", "CommonModule", 1)
        assert out is not None
        assert out["class"] == "header"  # not "executable" — BOM stripped
        assert out["executable"] is False
        # line 2 is the real first executable
        assert out["nearest_executable"] == 2
