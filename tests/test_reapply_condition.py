"""Regression: _reapply_bp_workspace must preserve BP conditions (PR#1 review #2)."""
import xml.etree.ElementTree as ET
from unittest.mock import AsyncMock

import pytest

from mcp_debug_server import RDBGClient


def _client():
    c = RDBGClient(debug_url="http://localhost:1550", infobase_alias="TestDB")
    c._post = AsyncMock(return_value=ET.Element("empty"))
    return c


@pytest.mark.asyncio
async def test_reapply_preserves_condition():
    c = _client()
    c._set_breakpoints_cache = [{
        "module_type": "ConfigModule", "object_id": "obj", "property_id": "prop",
        "lines": [41], "condition": 'Контрагент.ИНН = "123"',
    }]
    await c._reapply_bp_workspace()
    body = c._post.call_args.args[1]
    assert "condition" in body, "re-apply dropped the condition element"
    assert "Контрагент.ИНН" in body


@pytest.mark.asyncio
async def test_reapply_without_condition_omits_it():
    c = _client()
    c._set_breakpoints_cache = [{
        "module_type": "ConfigModule", "object_id": "o", "property_id": "p",
        "lines": [18], "condition": "",
    }]
    await c._reapply_bp_workspace()
    body = c._post.call_args.args[1]
    assert "condition" not in body