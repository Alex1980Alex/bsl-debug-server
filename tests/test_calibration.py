"""Line-calibration tools (debug_calibrate_lines / debug_calibrate_result).

Живой кейс 2026-07-07: строки repo/EDT-src смещены относительно deployed-
конфигурации (BP на 67 молчал, реальная строка 70). Калибровка = coverage-веер
(hit + auto-Continue) вокруг целевой строки → реальные исполняемые строки.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import mcp_debug_server as srv
from mcp_debug_server import RDBGClient


def _make_client(monkeypatch):
    c = RDBGClient(infobase_alias="ИБTest")
    c._attached = True
    c._registered = True
    monkeypatch.setattr(srv, "_client", c, raising=False)
    monkeypatch.setattr(srv, "_get_client", lambda: c)
    return c


OID = "cbb1b2f3-00ae-483f-8676-ea9f129b52c7"


@pytest.mark.asyncio
class TestCalibrateLines:
    async def test_arms_fan_and_registers_coverage(self, monkeypatch):
        c = _make_client(monkeypatch)
        set_calls = []

        async def _set_bps(self, **kw):
            set_calls.append(kw)
            return []

        monkeypatch.setattr(RDBGClient, "set_breakpoints", _set_bps)
        out = json.loads(await srv.debug_calibrate_lines(
            object_id=OID, line=67, radius=3))
        assert out["status"] == "calibration_armed"
        assert out["range"] == [64, 70]
        assert out["count"] == 7
        # веер ушёл одним set_breakpoints
        assert set_calls[0]["lines"] == list(range(64, 71))
        # coverage-ключи зарегистрированы (auto-Continue на fire)
        pid = c._calibrations[OID]["property_id"]
        assert all((OID, pid, ln) in c._coverage_tracked for ln in range(64, 71))
        # propertyID авто-резолвится для CommonModule
        assert pid and pid != "00000000-0000-0000-0000-000000000000"

    async def test_radius_clamped_and_line_floor(self, monkeypatch):
        _make_client(monkeypatch)

        async def _set_bps(self, **kw):
            return []

        monkeypatch.setattr(RDBGClient, "set_breakpoints", _set_bps)
        out = json.loads(await srv.debug_calibrate_lines(
            object_id=OID, line=2, radius=99))
        # radius clamp 30, floor строки = 1
        assert out["range"] == [1, 32]

    async def test_requires_connection(self, monkeypatch):
        c = _make_client(monkeypatch)
        c._attached = False
        out = json.loads(await srv.debug_calibrate_lines(object_id=OID, line=5))
        assert "error" in out


@pytest.mark.asyncio
class TestCalibrateResult:
    async def _arm(self, c, monkeypatch, requested=67, radius=3):
        async def _set_bps(self, **kw):
            return []

        monkeypatch.setattr(RDBGClient, "set_breakpoints", _set_bps)
        await srv.debug_calibrate_lines(
            object_id=OID, line=requested, radius=radius)
        return c._calibrations[OID]["property_id"]

    async def test_fired_lines_offset_and_cleanup(self, monkeypatch):
        c = _make_client(monkeypatch)
        pid = await self._arm(c, monkeypatch, radius=4)
        # эмулируем fire на 70 и 71 (реальный сдвиг +3 из живого кейса)
        c._coverage_tracked[(OID, pid, 70)]["hits"] = 1
        c._coverage_tracked[(OID, pid, 71)]["hits"] = 2
        posts = []

        async def _post(self, cmd, body, **kw):
            posts.append(cmd)
            return None

        async def _reapply(self):
            posts.append("reapply")

        monkeypatch.setattr(RDBGClient, "_post", _post)
        monkeypatch.setattr(RDBGClient, "_reapply_bp_workspace", _reapply)
        out = json.loads(await srv.debug_calibrate_result(object_id=OID))
        res = out["results"][0]
        assert res["fired_lines"] == [70, 71]
        assert res["nearest_fired"] == 70
        assert res["offset"] == 3
        # веер вычищен из coverage-трекера
        assert not any(k[0] == OID for k in c._coverage_tracked)
        # в BP-кэше остался ТОЛЬКО точечный BP на nearest
        entries = [e for e in c._set_breakpoints_cache if e["object_id"] == OID]
        assert entries and entries[0]["lines"] == [70]
        # workspace перепушен
        assert "reapply" in posts
        # калибровка снята
        assert OID not in getattr(c, "_calibrations", {})

    async def test_no_fire_gives_hint(self, monkeypatch):
        c = _make_client(monkeypatch)
        await self._arm(c, monkeypatch)
        posts = []

        async def _post(self, cmd, body, **kw):
            posts.append(cmd)
            return None

        monkeypatch.setattr(RDBGClient, "_post", _post)
        out = json.loads(await srv.debug_calibrate_result(object_id=OID))
        res = out["results"][0]
        assert res["fired_lines"] == []
        assert res["nearest_fired"] is None
        assert "hint" in res
        # кэш пуст → явный пустой bpWorkspace push (REPLACES-семантика)
        assert "setBreakpoints" in posts

    async def test_no_active_calibration(self, monkeypatch):
        _make_client(monkeypatch)
        out = json.loads(await srv.debug_calibrate_result())
        assert out["error"] == "no active calibration"

    async def test_keep_bp_false_removes_everything(self, monkeypatch):
        c = _make_client(monkeypatch)
        pid = await self._arm(c, monkeypatch)
        c._coverage_tracked[(OID, pid, 70)]["hits"] = 1

        async def _post(self, cmd, body, **kw):
            return None

        monkeypatch.setattr(RDBGClient, "_post", _post)
        out = json.loads(await srv.debug_calibrate_result(
            object_id=OID, keep_bp_on_nearest=False))
        assert out["results"][0]["nearest_fired"] == 70
        assert not [e for e in c._set_breakpoints_cache if e["object_id"] == OID]
