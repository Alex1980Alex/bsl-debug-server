"""C1 (roadmap 260708 W3) unit tests: setVariable / setExpression via RDBG
`modifyValue`.

Covers RDBGClient.modify_value request-building, _extract_modify_result on both
live-verified response shapes (success=newValueState/correctly,
failure=processed+errorDescr), and the debug_set_variable tool (guard
{old,new,changed}, verify on/off, not-connected/no-target envelopes).

Runtime semantics (modifyValue mutates a frame variable to the result of a BSL
value_expression; timeout is MILLISECONDS) were live-validated 2026-07-11 on
the MFM base — see pipeline/c1-set-variable/04-testing.md. These unit tests pin
the wire format + parsing so a regression is caught without a live base.
"""

from __future__ import annotations

import base64
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import mcp_debug_server as mds


def _b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


# --- RDBGClient.modify_value request builder ------------------------------
class TestModifyValueBuilder:
    @pytest.mark.asyncio
    async def test_builds_modifyvalue_request(self, monkeypatch):
        c = mds.RDBGClient(debug_url="http://x:1550", infobase_alias="IB")
        c.session_id = "sess-1"
        captured = {}

        async def fake_post(command, body, **kw):
            captured["command"] = command
            captured["body"] = body
            return ET.fromstring("<root/>")

        monkeypatch.setattr(c, "_post", fake_post)
        monkeypatch.setattr(c, "_ensure_target_attached", AsyncMock())
        await c.modify_value(name="Итог", value_expr="0", target_uuid="tgt", stack_level=2)

        assert captured["command"] == "modifyValue"
        b = captured["body"]
        assert "<debugRDBGRequestResponse:modifyDataPath>" in b
        assert "<debugRDBGRequestResponse:newValueInfo>" in b
        assert "<debugCalculations:stackLevel>2</debugCalculations:stackLevel>" in b
        assert "<debugCalculations:expression>Итог</debugCalculations:expression>" in b
        assert "<debugCalculations:itemType>expression</debugCalculations:itemType>" in b
        assert "<debugCalculations:variant>expr</debugCalculations:variant>" in b
        assert "<debugCalculations:valueExpression>0</debugCalculations:valueExpression>" in b
        assert "<debugRDBGRequestResponse:timeout>5000</debugRDBGRequestResponse:timeout>" in b

    @pytest.mark.asyncio
    async def test_escapes_special_chars_in_value_expr(self, monkeypatch):
        c = mds.RDBGClient(debug_url="http://x:1550", infobase_alias="IB")
        c.session_id = "s"
        captured = {}

        async def fake_post(command, body, **kw):
            captured["body"] = body
            return ET.fromstring("<root/>")

        monkeypatch.setattr(c, "_post", fake_post)
        monkeypatch.setattr(c, "_ensure_target_attached", AsyncMock())
        await c.modify_value(name="X", value_expr='Ф < 5 & "т"', target_uuid="tgt")
        b = captured["body"]
        # XML-escaped so the request stays well-formed (BSL comparison operators
        # and string literals would otherwise break the XML).
        assert "&lt;" in b and "&amp;" in b and "&quot;" in b
        assert "Ф < 5" not in b

    @pytest.mark.asyncio
    async def test_timeout_ms_override(self, monkeypatch):
        c = mds.RDBGClient(debug_url="http://x:1550", infobase_alias="IB")
        c.session_id = "s"
        captured = {}

        async def fake_post(command, body, **kw):
            captured["body"] = body
            return ET.fromstring("<root/>")

        monkeypatch.setattr(c, "_post", fake_post)
        monkeypatch.setattr(c, "_ensure_target_attached", AsyncMock())
        await c.modify_value(name="X", value_expr="1", target_uuid="tgt", timeout_ms=250)
        assert "<debugRDBGRequestResponse:timeout>250</debugRDBGRequestResponse:timeout>" in captured["body"]

    @pytest.mark.asyncio
    async def test_no_target_raises(self):
        c = mds.RDBGClient(debug_url="http://x:1550", infobase_alias="IB")
        c._last_stopped_target_id = None
        with pytest.raises(ValueError, match="no target_uuid"):
            await c.modify_value(name="X", value_expr="1", target_uuid=None)


# --- _extract_modify_result: both live-verified response shapes -----------
class TestExtractModifyResult:
    def test_success_shape_newvaluestate_correctly(self):
        parsed = [
            {
                "_tag": "newValueState",
                "evalResultState": "correctly",
                "resultValueInfo": {"valueDecimal": "777", "pres": _b64("777")},
            }
        ]
        processed, error = mds._extract_modify_result(parsed)
        assert processed is True
        assert error is None

    def test_failure_shape_processed_errordescr(self):
        parsed = [
            {"_tag": "processed", "_value": "false"},
            {"_tag": "errorDescr", "_value": _b64("{<Неизвестный модуль>(1)}: Деление на 0")},
        ]
        processed, error = mds._extract_modify_result(parsed)
        assert processed is False
        assert "Деление на 0" in error

    def test_with_errors_state_is_not_processed(self):
        parsed = [{"_tag": "newValueState", "evalResultState": "withErrors"}]
        processed, error = mds._extract_modify_result(parsed)
        assert processed is False

    def test_empty_response(self):
        assert mds._extract_modify_result([]) == (False, None)

    def test_non_dict_items_tolerated(self):
        assert mds._extract_modify_result(["junk", None, 42]) == (False, None)


# --- debug_set_variable tool ---------------------------------------------
class _FakeClient:
    def __init__(self):
        self._attached = True
        self._registered = True
        self.modify_value = AsyncMock(
            return_value=[
                {
                    "_tag": "newValueState",
                    "evalResultState": "correctly",
                    "resultValueInfo": {"pres": _b64("777")},
                }
            ]
        )
        # eval reads: first call → old (120), second → new (777)
        self.eval_expression = AsyncMock(
            side_effect=[
                [{"resultValueInfo": {"valueDecimal": "120"}}],
                [{"resultValueInfo": {"valueDecimal": "777"}}],
            ]
        )


@pytest.fixture
def _patch(monkeypatch):
    c = _FakeClient()
    monkeypatch.setattr(mds, "_get_client", lambda: c)
    monkeypatch.setattr(mds, "_resolve_stopped_target", AsyncMock(return_value=("tgt", [])))
    return c


@pytest.mark.asyncio
async def test_set_variable_guard(_patch):
    out = json.loads(
        await mds.debug_set_variable(name="ТаймаутСек", value_expression="777", target_id="tgt")
    )
    assert out["processed"] is True
    assert out["old"] == "120"
    assert out["new"] == "777"
    assert out["changed"] is True
    assert "security_note" in out
    assert _patch.eval_expression.await_count == 2  # before + after


@pytest.mark.asyncio
async def test_set_variable_verify_false_skips_reads(_patch):
    out = json.loads(
        await mds.debug_set_variable(
            name="X", value_expression="1", target_id="tgt", verify=False
        )
    )
    assert out["old"] is None and out["new"] is None and out["changed"] is None
    assert out["processed"] is True
    assert _patch.eval_expression.await_count == 0  # no reads when verify=False


@pytest.mark.asyncio
async def test_set_variable_not_connected(monkeypatch):
    c = _FakeClient()
    c._attached = False
    monkeypatch.setattr(mds, "_get_client", lambda: c)
    out = json.loads(await mds.debug_set_variable(name="X", value_expression="1"))
    assert out["error_type"] == "not_connected"


@pytest.mark.asyncio
async def test_set_variable_no_stopped_target(monkeypatch):
    c = _FakeClient()
    monkeypatch.setattr(mds, "_get_client", lambda: c)
    monkeypatch.setattr(mds, "_resolve_stopped_target", AsyncMock(return_value=("", [])))
    out = json.loads(await mds.debug_set_variable(name="X", value_expression="1"))
    assert out["error_type"] == "no_stopped_target"


@pytest.mark.asyncio
async def test_set_variable_surfaces_bsl_error(monkeypatch):
    """Bad value_expression → processed=false + error, tool does NOT crash."""
    c = _FakeClient()
    c.modify_value = AsyncMock(
        return_value=[
            {"_tag": "processed", "_value": "false"},
            {"_tag": "errorDescr", "_value": _b64("Деление на 0")},
        ]
    )
    c.eval_expression = AsyncMock(return_value=[{"resultValueInfo": {"valueDecimal": "120"}}])
    monkeypatch.setattr(mds, "_get_client", lambda: c)
    monkeypatch.setattr(mds, "_resolve_stopped_target", AsyncMock(return_value=("tgt", [])))
    out = json.loads(
        await mds.debug_set_variable(name="X", value_expression="1/0", target_id="tgt")
    )
    assert out["processed"] is False
    assert "Деление на 0" in out["error"]
