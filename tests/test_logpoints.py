"""Regression tests for logpoints: _scalar reducer + deferred eval (2026-06-04 fix)."""
import asyncio

import pytest

import logpoints


def _vi(**kw):
    return [{"_tag": "evalExprResBaseData", "evalResultState": "correctly",
             "resultValueInfo": kw}]


class TestScalar:
    def test_string(self):
        assert logpoints._scalar(_vi(valueString="0JHQkNCi0JwtMDAwOTIzOQ==")) == "БАТМ-0009239"

    def test_boolean(self):
        assert logpoints._scalar(_vi(valueBoolean="false")) == "Ложь"
        assert logpoints._scalar(_vi(valueBoolean="true")) == "Истина"

    def test_number(self):
        assert logpoints._scalar(_vi(valueDecimal="1")) == "1"

    def test_ref_pres_fallback(self):
        assert logpoints._scalar(_vi(typeName="ДокументСсылка.X", pres="MQ==")) == "1"

    def test_empty_list(self):
        assert logpoints._scalar([]) == ""

    def test_scalar_passthrough(self):
        assert logpoints._scalar(42) == 42

    def test_legacy_dict(self):
        assert logpoints._scalar({"presentation": "X"}) == "X"


class _MockClient:
    def __init__(self, logpoints_map):
        self._logpoints = logpoints_map
        self.session_id = "test-sess"
        self.eval_calls = []
        self.step_calls = []

    async def eval_expression(self, expression, target_uuid, stack_level=0):
        self.eval_calls.append(expression)
        return _vi(valueString="0JHQkNCi0Jw=")  # "БАТМ"

    async def step(self, action, target_id):
        self.step_calls.append((action, target_id))


def _stack():
    return [{"moduleID": {"objectID": "obj", "propertyID": "prop"}, "lineNo": "41"}]


@pytest.mark.asyncio
async def test_fire_logpoint_defers_eval_and_continues(tmp_path):
    key = ("obj", "prop", 41)
    client = _MockClient({key: "x={ВыражениеX}"})
    fired = await logpoints.fire_logpoint(client, "tgt", _stack(), tmp_path)
    assert fired is True
    # eval/step run in the DEFERRED task — pump the loop
    await asyncio.sleep(0.05)
    assert client.eval_calls == ["ВыражениеX"]
    assert client.step_calls == [("Continue", "tgt")]
    assert (tmp_path / "test-sess.jsonl").exists()


@pytest.mark.asyncio
async def test_fire_logpoint_no_match_returns_false(tmp_path):
    client = _MockClient({})
    assert await logpoints.fire_logpoint(client, "tgt", _stack(), tmp_path) is False
    await asyncio.sleep(0.01)
    assert client.eval_calls == []
    assert client.step_calls == []