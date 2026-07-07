"""
MCP Debug Server for 1C:Enterprise — Phase 6.8 (JAXB-compatible)
Connects directly to 1C debug agent (dbgs) via HTTP RDBG protocol.

Architecture:
    Claude Code -> MCP (stdio) -> this server -> HTTP RDBG -> 1C debug agent (port 1550)

Protocol reverse-engineered from bsl-debug-server-1.1-SNAPSHOT.jar (yukon39).
XML format: JAXB-compatible with <debugBaseData:request> root element.
URL format: {debugServerURL}/e1crdbg/rdbg?cmd={command}
Note: only 'ping' uses &dbgui={sessionId} in URL.
"""

import asyncio
import json
import logging
import re
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

import httpx
from mcp.server.fastmcp import FastMCP

# Local modules — UUID → path resolution + BSL local-name extraction
import bsl_locals
import uuid_index
import bp_conditions  # P0.A roadmap 260511
import logpoints  # P0.B roadmap 260511
import system_stops  # P0.D roadmap 260511
import artifacts  # P1.B roadmap 260511
import coverage as bsl_coverage  # P1.A roadmap 260511
import exception_bps  # P3.B roadmap 260511
import snapshot  # P2.A roadmap 260511
import autonomy  # A0/A1 roadmap 260708

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("1c-debug-mcp")

# XML namespaces
NS = {
    "base": "http://v8.1c.ru/8.3/debugger/debugBaseData",
    "rdbg": "http://v8.1c.ru/8.3/debugger/debugRDBGRequestResponse",
    "calc": "http://v8.1c.ru/8.3/debugger/debugCalculations",
    "auto": "http://v8.1c.ru/8.3/debugger/debugAutoAttach",
    "bp": "http://v8.1c.ru/8.3/debugger/debugBreakpoints",
    "rte": "http://v8.1c.ru/8.3/debugger/debugRTEFilter",
}

# Magic propertyID UUIDs per BSL module kind (yukon39/bsl-debug-server ModulePropertyId.java)
MODULE_PROPERTY_IDS = {
    "CommonModule": "d5963243-262e-4398-b4d7-fb16d06484f6",
    "ManagerModule": "d1b64a2c-8078-4982-8190-8f81aefda192",
    "ObjectModule": "a637f77f-3840-441d-a1c3-699c8c5cb7e0",
    "RecordSetModule": "9f36fd70-4bf4-47f6-b235-935f73aab43f",
    "FormModule": "32e087ab-1491-49b6-aba7-43571b41ac2b",
    "CommandModule": "078a6af8-d22c-4248-9c33-7e90075a3d2c",
}
ZERO_UUID = "00000000-0000-0000-0000-000000000000"


def _resolve_property_id(module_type: str, property_id: str = "") -> tuple[str, str]:
    """Resolve propertyID UUID from module_type when unset/zero.

    RDBG silently ignores BPs with zero/empty propertyID (see
    cache/dbgs-rdbg-debug-server.md §11). When property_id is empty or
    ZERO_UUID, look up MODULE_PROPERTY_IDS[module_type] and switch the wire
    module_type to "ConfigModule" (RDBG addresses config sub-modules by
    propertyID kind). An explicit non-zero property_id is returned unchanged
    with module_type intact.

    Returns (xml_module_type, property_id).

    W1.0.1 (2026-07-08): dedup of identical inline blocks previously in
    debug_set_breakpoint / debug_set_logpoint / debug_calibrate_lines /
    debug_coverage_register.
    """
    if not property_id or property_id == ZERO_UUID:
        kind_uuid = MODULE_PROPERTY_IDS.get(module_type, "")
        if kind_uuid:
            return "ConfigModule", kind_uuid
    return module_type, property_id


def _apply_line_offset(client, object_id: str, line: int) -> tuple[int, int]:
    """Apply cached per-module line offset (B2 roadmap 260708 §7.5).

    Deployed-config line numbers systematically drift from git/EDT source; a BP
    on the git line silently doesn't fire. `debug_calibrate_result` records the
    measured offset per object_id (offset = nearest_fired − requested). This
    applies it so a git-line BP lands on the deployed line without manual
    calibration each time.

    Returns (adjusted_line, applied_offset). No cached offset → line unchanged,
    offset 0.
    """
    offsets = getattr(client, "_line_offsets", None) or {}
    off = offsets.get(object_id, 0)
    return (line + off if off else line), off


def _build_request(*children_xml: str) -> str:
    """Build a JAXB-compatible RDBG XML request string.

    All children_xml strings are inserted raw inside <debugBaseData:request>.
    """
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<debugBaseData:request"
        f' xmlns:debugRDBGRequestResponse="{NS["rdbg"]}"'
        f' xmlns:debugBaseData="{NS["base"]}"'
        f' xmlns:debugCalculations="{NS["calc"]}"'
        f' xmlns:debugAutoAttach="{NS["auto"]}"'
        f' xmlns:debugBreakpoints="{NS["bp"]}"'
        f' xmlns:debugRTEFilter="{NS["rte"]}"'
        ">" + "".join(children_xml) + "</debugBaseData:request>"
    )


def _rdbg(tag: str, text: str = "") -> str:
    return f"<debugRDBGRequestResponse:{tag}>{text}</debugRDBGRequestResponse:{tag}>"


def _base(tag: str, text: str = "") -> str:
    return f"<debugBaseData:{tag}>{text}</debugBaseData:{tag}>"


def _calc(tag: str, text: str = "") -> str:
    return f"<debugCalculations:{tag}>{text}</debugCalculations:{tag}>"


def _auto(tag: str, text: str = "") -> str:
    return f"<debugAutoAttach:{tag}>{text}</debugAutoAttach:{tag}>"


def _bp(tag: str, text: str = "") -> str:
    return f"<debugBreakpoints:{tag}>{text}</debugBreakpoints:{tag}>"


def _rte(tag: str, text: str = "") -> str:
    return f"<debugRTEFilter:{tag}>{text}</debugRTEFilter:{tag}>"


def _target_id_light(target_uuid: str) -> str:
    """Build <debugBaseData:id>uuid</debugBaseData:id> inside a parent."""
    return _base("id", target_uuid)


def _strip_ns(tag: str) -> str:
    return tag.split("}")[-1] if "}" in tag else tag


def _parse_element(elem: ET.Element) -> dict:
    """Recursively parse an XML element into a dict."""
    result: dict = {"_tag": _strip_ns(elem.tag)}
    for child in elem:
        ctag = _strip_ns(child.tag)
        if len(child) == 0:
            result[ctag] = child.text.strip() if child.text else ""
        else:
            existing = result.get(ctag)
            if isinstance(existing, list):
                existing.append(_parse_element(child))
            elif existing is not None:
                result[ctag] = [existing, _parse_element(child)]
            else:
                result[ctag] = _parse_element(child)
    if not any(k != "_tag" for k in result):
        result["_value"] = elem.text.strip() if elem.text else ""
    return result


def _parse_response(root: ET.Element) -> list[dict]:
    """Parse XML response into list of dicts."""
    results = []
    for item in root:
        tag = _strip_ns(item.tag)
        if len(item) == 0:
            if item.text and item.text.strip():
                results.append({"_tag": tag, "_value": item.text.strip()})
        else:
            results.append(_parse_element(item))
    return results


def _escape_xml(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def _build_bp_info_xml(line: int, condition: str = "") -> str:
    children = _bp("line", str(line)) + _bp("isActive", "true")
    if condition:
        children += _bp("condition", _escape_xml(condition))
    children += _bp("temp", "false")
    children += _bp("user", "true")  # yukon39 BreakpointInfo.user — dbgs halt только для user-BP
    return _bp("bpInfo", children)


def _aggregate_breakpoints(cache: list, new_entry: dict) -> dict:
    """Merge cached BP entries + new entry into per-module groups.

    RDBG `setBreakpoints` команда REPLACES workspace при каждом вызове —
    multi-line BPs одного модуля и multi-module BPs должны идти ОДНИМ
    request'ом (multiple `moduleBPInfo` elements в `bpWorkspace`). Wrapper
    aggregates все cached BPs (плюс new_entry) и каждый submit отправляет
    full workspace, иначе предыдущие BPs теряются (live finding 2026-05-10).

    Returns: dict keyed by 7-tuple
        (module_type, object_id, property_id, ext_id, url, extension_name, version)
    value = dict[line:int, condition:str] (P0.A roadmap 260511).
    """
    grouped: dict = {}
    for entry in list(cache) + [new_entry]:
        key = (
            entry["module_type"],
            entry["object_id"],
            entry["property_id"],
            entry.get("ext_id", 0) or 0,
            entry.get("url", "") or "",
            entry.get("extension_name", "") or "",
            entry.get("version", "") or "",
        )
        line_map: dict = grouped.setdefault(key, {})
        cond = entry.get("condition", "") or ""
        for line in entry.get("lines", []):
            try:
                line_map[int(line)] = cond
            except (TypeError, ValueError):
                continue
    return {k: dict(sorted(v.items())) for k, v in grouped.items()}


class RDBGClient:
    """HTTP client for 1C debug agent RDBG protocol (JAXB-compatible)."""

    HEADERS = {
        "Accept": "application/xml",
        "Content-Type": "application/xml; charset=utf-8",
        "User-Agent": "1CV8",
    }

    def __init__(self, debug_url: str = "http://localhost:1550", infobase_alias: str = "DefAlias"):
        self.debug_url = debug_url.rstrip("/")
        self.infobase_alias = infobase_alias
        self.session_id = str(uuid.uuid4())
        self._http = httpx.AsyncClient(timeout=30.0, headers=self.HEADERS)
        self._attached = False
        self._registered = False
        self._ping_task: Optional[asyncio.Task] = None

        # Roadmap §13 (post-BP-fire handshake): event-loop state.
        # Set by _handle_command() when ping returns DBGUIExtCmdInfo* events.
        # Mirrors yukon39 ContextServerEventSubscriber + Debugee.run() dispatch.
        self._stopped_targets: set[str] = set()  # targets currently in stop state
        self._last_stopped_target_id: Optional[str] = None
        self._last_stack_by_target: dict[str, list[dict]] = {}
        self._stop_reason_by_target: dict[str, str] = {}  # "breakpoint" | "step" | "exception"
        self._last_exception_by_target: dict[str, dict] = {}
        self._known_attached_targets: set[str] = set()  # idempotency for auto-attach
        # P0.A roadmap 260511: hit-condition counters per (object_id, property_id, line).
        # RDBG не имеет native hit-count → wrapper-level enforcement в _handle_command.
        self._hit_conditions: dict[tuple, str] = {}  # (oid,pid,line) -> ">5" | "%3" | "=10"
        self._hit_counters: dict[tuple, int] = {}  # (oid,pid,line) -> count
        # P0.B roadmap 260511: logpoint templates per (object_id, property_id, line).
        # На callStackFormed: render → write JSONL → auto-Continue (no user-visible halt).
        self._logpoints: dict[tuple, str] = {}  # (oid,pid,line) -> "Контр={Контр.ИНН}"
        self._log_dir: Path = Path(__file__).parent / "data" / "debug_logs"
        # P0.D roadmap 260511: armed by set_break_on_next_statement; cleared after first stop.
        # Used by system_stops.maybe_auto_continue_system_stop to keep user-requested stops visible.
        self._break_on_next_armed: bool = False
        # P0.G roadmap 260511: silent-arm variant — break_on_next halts next rphost,
        # wrapper grabs target_id from event, attaches it, drains BPs, Continues
        # silently (no user-visible stop). Closes HTTPService warm-pool BP-fire gap.
        self._break_on_next_silent_arm: bool = False
        # #1 Sticky capture-mode (2026-06-03): when True, break-on-next is re-armed
        # after every drain so EVERY newly spawned target (incl. fast background JOB
        # rphosts) halts at its first statement until BPs propagate — defeats the
        # attach/BP race that makes BPs miss in short-lived JOB rphosts. Default off
        # → existing behaviour unchanged. Toggled via debug_capture_mode tool.
        self._capture_mode: bool = False
        # P0.E roadmap 260511: targets freshly spawned + auto-attached. First cascade
        # halt for these acts as BP-propagation window (drain BPs, wait, Continue).
        self._attached_pending: set[str] = set()
        # P1.A roadmap 260511: coverage tracker — (oid, pid, line) -> {hits, file_path}.
        # Silent BP-counter; coverage.record_hit_and_continue auto-Continues invisibly.
        self._coverage_tracked: dict[tuple, dict] = {}
        # P3.B roadmap 260511: exception BP filters. Empty list = halt all exceptions
        # (backward compat). Non-empty = halt only if any filter matches.
        self._exception_bp_filters: list[dict] = []
        # P2.A roadmap 260511: snapshot replay — when True, every stop event
        # (callStackFormed + rteProcessing) appends entry to debug_replays JSONL.
        self._recording_enabled: bool = False

        # P2.4 client-side BP cache (matches yukon39 BreakpointsManager pattern —
        # RDBG не имеет server-side getBreakpoints URL, поэтому ведём cache локально).
        # Keyed by (object_id, property_id), value = full set_breakpoints request payload.
        self._set_breakpoints_cache: list[dict] = []

        # Async eval pickup: evalExpr returns immediately (often with empty result
        # when calcWaitingTime expires); the actual computed value arrives later
        # via `exprEvaluated` event in ping_loop. Map expressionResultID → Future.
        # Resolved by _handle_command's exprEvaluated branch; awaited in eval_expression.
        self._pending_evals: dict[str, asyncio.Future] = {}

        # §12.3 Level 3 — session metrics tracking (append-only counters)
        from datetime import datetime as _dt

        self._session_started_at = _dt.now().isoformat()
        self._bp_set_count = 0
        self._bp_fire_count = 0
        self._bp_by_location: dict = {}  # "obj_id:line" → fire count
        self._eval_count = 0
        self._eval_failures = 0
        self._eval_errors: list = []  # last N error strings
        self._ui_plus_retry_count = 0
        self._recycle_method_used: Optional[str] = None
        self._force_recycle_invoked = False
        self._stop_events: list = []  # [{ts, target_id, lineNo}]
        self._rphosts_seen: set = set()

    async def _post(
        self, command: str, body: str, include_dbgui_url: bool = False, _ui_plus_retry: bool = True
    ) -> ET.Element:
        """POST to RDBG endpoint. Only ping uses dbgui in URL.

        UI+ auto-retry (2026-05-10): if RDBG returns 400 with \u00abUI+ \u0447\u0430\u0441\u0442\u044c
        \u043e\u0442\u043b\u0430\u0434\u043a\u0438 \u043d\u0435 \u0437\u0430\u0440\u0435\u0433\u0438\u0441\u0442\u0440\u0438\u0440\u043e\u0432\u0430\u043d\u0430\u00bb (the \u00abUI+ debug part not registered\u00bb
        error), re-issue the post-attach handshake (initSettings +
        clearBreakOnNextStatement) and retry the original call once.
        Live testing showed UI+ part can be revoked between operations on
        RDBG 8.3.27.1936 \u2014 root cause unknown, but reapplying handshake
        restores UI+ for subsequent ops. Set `_ui_plus_retry=False` for
        the handshake calls themselves to prevent infinite recursion.
        """
        url = f"{self.debug_url}/e1crdbg/rdbg?cmd={command}"
        if include_dbgui_url:
            url += f"&dbgui={self.session_id}"
        log.debug("POST %s", url)
        resp = await self._http.post(url, content=body)
        if resp.status_code >= 400:
            err_body = (resp.text or "")[:2000]
            # UI+ revocation auto-recovery: detect Russian + English error texts.
            ui_plus_lost = (
                _ui_plus_retry
                and resp.status_code == 400
                and command
                not in (
                    "initSettings",
                    "clearBreakOnNextStatement",
                    "attachDebugUI",
                    "detachDebugUI",
                )
                and (
                    "UI+ - \u0447\u0430\u0441\u0442\u044c \u043e\u0442\u043b\u0430\u0434\u043a\u0438 \u043d\u0435 \u0437\u0430\u0440\u0435\u0433\u0438\u0441\u0442\u0440\u0438\u0440\u043e\u0432\u0430\u043d\u0430"
                    in err_body
                    or "UI+ debug part not registered" in err_body
                )
            )
            if ui_plus_lost:
                return await self._ui_plus_recover_and_retry(
                    command,
                    body,
                    include_dbgui_url,
                    resp,
                    err_body,
                )
            log.error("RDBG %s -> HTTP %s body=%s", command, resp.status_code, err_body)
            raise httpx.HTTPStatusError(
                f"RDBG {command} {resp.status_code}: {err_body}",
                request=resp.request,
                response=resp,
            )
        text = resp.text.lstrip("\ufeff")
        if not text:
            return ET.Element("empty")
        return ET.fromstring(text)

    async def _ui_plus_recover_and_retry(
        self, command, body, include_dbgui_url, failed_resp, err_body
    ):
        """Two-stage UI+ recovery: light handshake → escalate to full re-attach.

        Live test 2026-05-10: when UI+ is revoked, even initSettings itself
        returns 400 UI+. Original v3 logic re-raised at that point — never
        reached escalation. v4 fix: if light handshake itself fails (or
        light retry fails), proceed unconditionally to Stage 2 re-attach.
        """
        log.warning("RDBG %s → UI+ revoked; trying light re-handshake", command)
        # §12.3 Level 3 — track UI+ retry для session_summary
        self._ui_plus_retry_count += 1
        light_failed = False
        try:
            await self.init_settings()
            await self.clear_break_on_next_statement()
        except Exception as e:
            log.warning("UI+ light re-handshake failed (%s); will escalate", e)
            light_failed = True
        if not light_failed:
            try:
                return await self._post(
                    command, body, include_dbgui_url=include_dbgui_url, _ui_plus_retry=False
                )
            except httpx.HTTPStatusError as light_err:
                if not self._is_ui_plus_lost(light_err):
                    raise
        log.warning("RDBG %s → escalating to full detach+attach", command)
        return await self._ui_plus_full_reattach_and_retry(command, body, include_dbgui_url)

    async def _ui_plus_full_reattach_and_retry(self, command, body, include_dbgui_url):
        """Stage 2 escalation: detach + new attachDebugUI + 4-step handshake."""
        old_sid = self.session_id
        try:
            await self.detach()
        except Exception:
            pass
        self.session_id = str(uuid.uuid4())
        self._attached = False
        self._registered = False
        if self._ping_task and not self._ping_task.done():
            self._ping_task.cancel()
            self._ping_task = None
        await self.attach(cleanup_stale=False)
        if self._registered:
            await self.init_settings()
            await self.clear_break_on_next_statement()
            await self.set_auto_attach_settings()
        log.info("UI+ escalation: re-attached %s → %s", old_sid[:8], self.session_id[:8])
        return await self._post(
            command, body, include_dbgui_url=include_dbgui_url, _ui_plus_retry=False
        )

    @staticmethod
    def _is_ui_plus_lost(err: "httpx.HTTPStatusError") -> bool:
        """True iff response is 400 with «UI+ часть отладки не зарегистрирована»."""
        body = (err.response.text or "")[:500]
        return err.response.status_code == 400 and (
            "UI+ - часть отладки не зарегистрирована" in body
            or "UI+ debug part not registered" in body
        )

    def _base_fields(self) -> str:
        """Common fields: infoBaseAlias + idOfDebuggerUI."""
        return _rdbg("infoBaseAlias", self.infobase_alias) + _rdbg(
            "idOfDebuggerUI", self.session_id
        )

    # -- Connection API ----------------------------------------------------

    async def get_api_version(self) -> str:
        body = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            f'<MiscRDbgGetAPIVerRequest xmlns="{NS["rdbg"]}"/>'
        )
        root = await self._post("getRDbgAPIVer", body)
        for elem in root.iter():
            if _strip_ns(elem.tag) == "version" and elem.text:
                return elem.text
        return "unknown"

    async def get_debug_id(self) -> Optional[str]:
        """Get existing debug UI session ID (if any debugger is attached)."""
        body = _build_request(self._base_fields())
        root = await self._post("getDebugID", body)
        for elem in root.iter():
            if _strip_ns(elem.tag) == "idOfDebugUI" and elem.text:
                return elem.text.strip()
        return None

    async def attach(self, cleanup_stale: bool = True) -> dict:
        """Attach as debug UI. Returns 'registered' or 'ibInDebug'.

        Roadmap §6.3 (2026-05-09): cleanup_stale=True пытается detach
        существующую Debug UI session с тем же infobase_alias перед attach —
        защита от race window после wrapper crash без graceful detach (старая
        session живёт в dbgs.exe ~60с до GC, новый wrapper попадает на
        `ibInDebug`). Не bullet-proof: getDebugID возвращает только OUR
        session_id, чужие debug UI (EDT/Конфигуратор) этим не сбросить.
        """
        if cleanup_stale:
            await self._cleanup_stale_session()
        # Empty <options/> mirrors yukon39 ServerContext.attach() line 102:
        # `new DebuggerOptions()` без сеттеров → JAXB serializes empty element.
        # Pre-2026-05-10 wrapper sent <options><foregroundAbility>false</...
        # which doesn't match yukon39 production. Pure speculation that this
        # affects UI+ persistence — verify in live test.
        body = _build_request(
            self._base_fields(),
            _rdbg("options"),
        )
        root = await self._post("attachDebugUI", body)
        result = "unknown"
        for elem in root.iter():
            if _strip_ns(elem.tag) == "result" and elem.text:
                result = elem.text.strip()
        self._attached = True
        self._registered = result == "registered"
        # Background ping keeps RDBG session alive — без него dbgs.exe GC-нет UI
        if self._registered and (self._ping_task is None or self._ping_task.done()):
            self._ping_task = asyncio.create_task(self._ping_loop())
        # §13.x HMR-recovery: snapshot session for next subprocess respawn.
        # Covers BOTH initial attach() in debug_connect() AND the escalation
        # path in _ui_plus_full_reattach_and_retry (which regenerates session_id
        # then calls attach() again — so the new id overwrites the stale file).
        if self._registered:
            _persist_active_session(self)
        return {
            "result": result,
            "session_id": self.session_id,
            "fully_registered": self._registered,
        }

    async def _cleanup_stale_session(self) -> None:
        """Probe getDebugID — если existing session ID найден, попытаться detach.

        Roadmap §6.3: После wrapper crash без detach старая session живёт в
        dbgs.exe ~60с. Новый wrapper-instance с FRESH session_id всё равно
        получит «ibInDebug» т.к. RDBG считает infobase занятой. Workaround:
        перед attach спросить getDebugID и для каждой найденной (читай:
        нашей prior session, ассоциированной с infoBaseAlias) попытаться
        detachDebugUI с её session_id.

        Лимиты: getDebugID возвращает ОДИН id (а не список); если у RDBG
        нет конкретно-нашей prior session, вернёт пустоту. Если есть —
        detach по нему очистит slot.
        """
        try:
            stale_id = await self.get_debug_id()
            if stale_id and stale_id != self.session_id and stale_id != ZERO_UUID:
                log.info(
                    "[cleanup_stale] existing debug UI session %s found, attempting detach",
                    stale_id[:8],
                )
                detach_body = _build_request(
                    _rdbg("infoBaseAlias", self.infobase_alias),
                    _rdbg("idOfDebuggerUI", stale_id),
                )
                try:
                    await self._post("detachDebugUI", detach_body)
                    log.info("[cleanup_stale] stale session %s detached", stale_id[:8])
                except Exception as e:
                    log.debug("[cleanup_stale] detach failed (may be OK): %s", e)
        except Exception as e:
            log.debug("[cleanup_stale] getDebugID failed (no stale session): %s", e)

    # #2 (roadmap 260603): adaptive ping cadence. RDBG pingDebugUIParams возвращает
    # снапшот очереди немедленно (не server-held long-poll), поэтому латентность =
    # интервал сна. Idle → 2с (heartbeat, dbgs GC'нет debug UI ~60с). Active (ждём
    # событие: capture-mode / armed break-on-next / pending-drain) → 0.1с: быстрая
    # доставка targetStarted сужает окно гонки attach/BP в коротких JOB rphost.
    PING_INTERVAL_IDLE = 2.0
    PING_INTERVAL_ACTIVE = 0.1
    POST_SPAWN_POLL_SEC = 6.0  # time-based auto-attach diff (≈ legacy 3×2с)

    async def _ping_loop(self) -> None:
        """Periodic ping: keep session alive. Dispatch happens inside ping().

        Pre-2026-05-10: this loop maintained its own _handle_command dispatch
        AFTER calling ping(), while ping() itself did not dispatch. That
        bifurcated the event-processing path — manual debug_ping (MCP tool)
        could drain the RDBG queue without populating cache, leading to a
        cache-miss in subsequent debug_stack_trace calls.

        Post-fix: ping() dispatches inline. This loop just keeps the session
        alive (heartbeat — без него dbgs.exe GC'нет debug UI ~60с) и
        делегирует обработку событий в ping().

        Roadmap 260511 §P0.4 (2026-05-11): каждые ~POST_SPAWN_POLL_SEC секунд
        (time-based, ~6с — независимо от каденса ping, см. roadmap 260603 §8)
        дополнительно вызывает get_targets() и
        diff'ит против _known_attached_targets. Закрывает residual RC2 gap:
        HTTP-service spawned rphost'ы (через 1c-mcp-crud execute_code) видны
        в getDbgAllTargetStates, но НЕ emit'ят DBGUIExtCmdInfoStarted к
        нашей session → без polling attach_debug_targets никогда не
        вызовется → BPs не fire. Polling auto-attach'ит такие targets.
        """
        try:
            elapsed_since_poll = 0.0
            while self._attached and self._registered:
                # #2 (roadmap 260603): adaptive cadence — быстрый poll когда ждём
                # событие (имеем armed break-on-next / capture-mode / pending-drain),
                # иначе 2с heartbeat. Сужает окно гонки доставки targetStarted для
                # короткоживущих JOB rphost. Default-путь (ничего не armed) = 2с, как
                # прежде → поведение не меняется.
                active = (
                    self._capture_mode
                    or self._break_on_next_silent_arm
                    or self._break_on_next_armed
                    or bool(self._attached_pending)
                )
                interval = self.PING_INTERVAL_ACTIVE if active else self.PING_INTERVAL_IDLE
                await asyncio.sleep(interval)
                try:
                    await self.ping()  # dispatches internally
                except Exception as e:
                    log.debug("ping failed: %s", e)
                # Time-based (не per-iteration) auto-attach diff: ~6с независимо от
                # каденса ping'а, чтобы fast-poll не молотил getDbgAllTargetStates.
                elapsed_since_poll += interval
                if elapsed_since_poll >= self.POST_SPAWN_POLL_SEC:
                    elapsed_since_poll = 0.0
                    try:
                        await self._post_spawn_auto_attach()
                    except Exception as e:
                        log.debug("post-spawn poll failed: %s", e)
        except asyncio.CancelledError:
            pass

    async def _post_spawn_auto_attach(self) -> int:
        """Detect targets not yet attached + attach them. Roadmap 260511 §P0.4.

        Background polling, вызывается из _ping_loop каждые ~6с. Получает
        список всех target'ов от RDBG (`getDbgAllTargetStates`), сравнивает
        с `_known_attached_targets`, attach'ит любые новые.

        Закрывает design-level pattern для RC2: HTTP-service spawned rphost
        emit'ит targetStarted событие, но event может потеряться (HMR-restart
        race, EOF на ping queue, etc.). Periodic poll provides eventual
        attachment guarantee если RDBG отдаёт rphost через getDbgAllTargetStates.

        ⚠ **P0.5 caveat (E2E finding 2026-05-11):** в RDBG 8.3.27
        `getDbgAllTargetStates` возвращает ТОЛЬКО targets, которые
        зарегистрировались к нашей Debug UI session через
        `DBGUIExtCmdInfoStarted` event. HTTP-service spawned rphost'ы
        (через `1c-mcp-crud:execute_code`) fundamentally НЕ регистрируются
        к UI session — они видны на OS-level (`detect_pre_existing_rphosts`)
        но НЕ в `getDbgAllTargetStates` response. Polling sees empty list →
        polling не помогает в этом сценарии. Требует P0.5 follow-up: research
        cluster-process-UUID → debug-UUID mapping API (yukon39 reference +
        RDBG protocol exploration). См. roadmap 260511 §P0.5.

        Race note: `_handle_command(targetStarted)` параллельно может добавить
        target в `_known_attached_targets`. На race возможен двойной attach;
        RDBG idempotent (повторный attach OK), но `log.info` сдублируется.

        Returns: количество newly attached targets (для логирования / тестов).
        """
        try:
            targets = await self.get_targets()
        except Exception as e:
            log.debug("post-spawn poll get_targets failed: %s", e)
            return 0
        new_ids: list[str] = []
        for t in targets:
            tid = t.get("id")
            if tid and tid not in self._known_attached_targets:
                new_ids.append(tid)
        if not new_ids:
            return 0
        try:
            await self.attach_debug_targets(new_ids, attach=True)
            for tid in new_ids:
                self._known_attached_targets.add(tid)
            log.info(
                "[post-spawn] auto-attached %d new target(s): %s",
                len(new_ids),
                [tid[:8] for tid in new_ids],
            )
            return len(new_ids)
        except Exception as e:
            log.warning("post-spawn attach failed: %s", e)
            return 0

    # Real-world finding 2026-05-09 §13.18: RDBG может emit `cmdIDNum=N` без
    # literal `cmdId="literal"`. Map ordinal → cmdId per yukon39 DBGUIExtCmds
    # enum order (see DBGUIExtCmds.java).
    _CMD_ID_NUM_TO_LITERAL = {
        "0": "unknown",
        "1": "targetStarted",
        "2": "targetQuit",
        "3": "correctedBP",
        "4": "rteProcessing",
        "5": "rteOnBPConditionProcessing",
        "6": "measureResultProcessing",
        "7": "callStackFormed",
        "8": "exprEvaluated",
        "9": "valueModified",
        "10": "errorViewInfo",
        "11": "ForegroundHelperSet",
        "12": "ForegroundHelperRequest",
        "13": "ForegroundHelperProcess",
    }

    async def _handle_command(self, cmd: dict) -> None:
        """Process single DBGUIExtCmdInfo* event from ping response.

        Roadmap §13.12 spec — see cache/dbgs-rdbg-debug-server.md.
        XML wire literal `cmdId` (lowercase) is matched; if absent, fallback
        on `cmdIDNum` ordinal mapping (real-world finding §13.18 — production
        RDBG sometimes emits cmdIDNum without literal cmdId).
        """
        cmd_type = cmd.get("cmdId") or ""
        if not cmd_type:
            num = cmd.get("cmdIDNum") or ""
            if isinstance(num, str) and num in self._CMD_ID_NUM_TO_LITERAL:
                cmd_type = self._CMD_ID_NUM_TO_LITERAL[num]
                log.debug("[event] cmdId derived from cmdIDNum=%s -> %s", num, cmd_type)
        # Extract target_id — payload может иметь nested targetID или targetIDStr
        target_id = self._extract_target_id(cmd)

        if cmd_type == "targetStarted":
            # 🔴 CRITICAL: auto-attach NEW targets (rphost при posting документа)
            if target_id and target_id not in self._known_attached_targets:
                try:
                    await self.attach_debug_targets([target_id])
                    self._known_attached_targets.add(target_id)
                    log.info("[event] Started: target %s → attached", target_id[:8])
                    # ⚠ CORRECTION (deep research 2026-06-03, roadmap 260603 §10):
                    # RDBG `setBreakpoints` — SESSION-GLOBAL, НЕ per-target (запрос
                    # несёт только bpWorkspace + idOfDebuggerUI, без target-id);
                    # сервер dbgs САМ пропагирует workspace каждому авто-attach'енному
                    # таргету. yukon39 ставит BP один раз на сессию и НЕ ре-применяет
                    # per-target. Поэтому правильная модель — регистрировать
                    # bpWorkspace session-global ДО спавна JOB (что и делает
                    # debug_set_breakpoint). Этот re-apply оставлен лишь как BACKSTOP
                    # (HMR-recovery / потеря workspace), НЕ как primary-механизм — на
                    # эфемерном JOB реактивный per-target re-apply проигрывает гонку.
                    if self._set_breakpoints_cache:
                        try:
                            await self._reapply_bp_workspace()
                            log.debug("[event] BPs re-applied for target %s", target_id[:8])
                        except Exception as e:
                            log.warning("BP re-apply failed for %s: %s", target_id[:8], e)
                    # P0.E: mark target as pending BP-propagation drain.
                    # First cascade halt for this target → drain BPs + brief wait + Continue.
                    self._attached_pending.add(target_id)
                except Exception as e:
                    log.warning("auto-attach failed for %s: %s", target_id[:8], e)

        elif cmd_type == "callStackFormed":
            # 🔴 CRITICAL: stop event — stack уже в payload, no pull request needed
            if not target_id:
                log.warning("callStackFormed without target_id, skipping")
                return
            self._stopped_targets.add(target_id)
            self._last_stopped_target_id = target_id
            stack_raw = cmd.get("callStack")
            stack: list[dict] = []
            if isinstance(stack_raw, list):
                stack = stack_raw
            elif isinstance(stack_raw, dict):
                stack = [stack_raw]
            self._last_stack_by_target[target_id] = stack
            stop_by_bp = str(cmd.get("stopByBP", "")).lower() == "true"
            self._stop_reason_by_target[target_id] = "breakpoint" if stop_by_bp else "step"
            log.info(
                "[event] CallStackFormed: target=%s frames=%d reason=%s",
                target_id[:8],
                len(stack),
                self._stop_reason_by_target[target_id],
            )
            # P0.D roadmap 260511: filter system-initiated stops (spawn-halt, stop_on_next)
            system_stop_suppressed = await system_stops.maybe_auto_continue_system_stop(
                self,
                target_id,
                stop_by_bp,
            )
            if system_stop_suppressed:
                return
            # Clear break_on_next flag: user got the stop they armed
            if self._break_on_next_armed:
                self._break_on_next_armed = False
            # P1.A roadmap 260511: coverage hit (silent counter, auto-Continue)
            coverage_hit = False
            if stop_by_bp and stack and self._coverage_tracked:
                coverage_hit = await bsl_coverage.record_hit_and_continue(
                    self,
                    target_id,
                    stack,
                )
            if coverage_hit:
                return
            # P0.B roadmap 260511: logpoint check (render+log+auto-Continue, never user-visible)
            logpoint_fired = False
            if stop_by_bp and stack and self._logpoints:
                logpoint_fired = await logpoints.fire_logpoint(
                    self,
                    target_id,
                    stack,
                    self._log_dir,
                )
            # P0.A roadmap 260511: hit_condition enforcement
            hit_condition_suppressed = False
            if not logpoint_fired and stop_by_bp and stack and self._hit_conditions:
                hit_condition_suppressed = await bp_conditions.auto_continue_if_unsatisfied(
                    self,
                    target_id,
                    stack,
                )
            # Suppressed stops (logpoint/hit_condition not satisfied) — auto-Continue'd,
            # user never saw them → don't pollute _stop_events/_bp_fire_count metrics.
            stop_suppressed = logpoint_fired or hit_condition_suppressed
            # §12.3 Level 3 — track stop event для session_summary
            from datetime import datetime as _dt

            top = stack[0] if stack else {}
            line_no = top.get("lineNo", "?") if isinstance(top, dict) else "?"
            obj_id_top = ""
            if isinstance(top, dict):
                mod_id = top.get("moduleID")
                if isinstance(mod_id, dict):
                    obj_id_top = mod_id.get("objectID", "")
            if not stop_suppressed:
                self._stop_events.append(
                    {
                        "ts": _dt.now().isoformat(),
                        "target_id": target_id,
                        "lineNo": line_no,
                        "reason": self._stop_reason_by_target[target_id],
                    }
                )
                self._rphosts_seen.add(target_id)
            if stop_by_bp and not stop_suppressed:
                self._bp_fire_count += 1
                if obj_id_top and line_no != "?":
                    key = f"{obj_id_top}:{line_no}"
                    self._bp_by_location[key] = self._bp_by_location.get(key, 0) + 1
            # P2.A roadmap 260511: replay snapshot recording (after metrics gate so
            # only user-visible stops are recorded)
            if not stop_suppressed:
                snapshot.record(
                    self, target_id, self._stop_reason_by_target.get(target_id, "bp"), stack
                )

        elif cmd_type == "rteProcessing":
            # 🟠 IMPORTANT: unhandled exception — also a stop event
            if not target_id:
                log.warning("rteProcessing without target_id, skipping")
                return
            self._stopped_targets.add(target_id)
            self._last_stopped_target_id = target_id
            stack_raw = cmd.get("callStack")
            stack = (
                stack_raw
                if isinstance(stack_raw, list)
                else [stack_raw]
                if isinstance(stack_raw, dict)
                else []
            )
            self._last_stack_by_target[target_id] = stack
            self._stop_reason_by_target[target_id] = "exception"
            exc = cmd.get("exception")
            if isinstance(exc, dict):
                self._last_exception_by_target[target_id] = exc
            log.warning(
                "[event] RTE: target=%s exception_present=%s frames=%d",
                target_id[:8],
                bool(exc),
                len(stack),
            )
            # P3.B roadmap 260511: exception BP filter — if defined and none match,
            # auto-Continue silently (don't pollute stop_events with filtered out exc).
            if self._exception_bp_filters:
                suppressed = await exception_bps.maybe_suppress(
                    self,
                    target_id,
                    exc,
                    stack,
                )
                if suppressed:
                    return
            # P2.A roadmap 260511: replay snapshot for user-visible exception
            snapshot.record(
                self, target_id, "exception", stack, exc if isinstance(exc, dict) else None
            )

        elif cmd_type == "targetQuit":
            if target_id:
                self._stopped_targets.discard(target_id)
                self._last_stack_by_target.pop(target_id, None)
                self._stop_reason_by_target.pop(target_id, None)
                self._last_exception_by_target.pop(target_id, None)
                self._known_attached_targets.discard(target_id)
                self._attached_pending.discard(target_id)  # P0.F: prevent leak
                log.info("[event] Quit: target=%s", target_id[:8])
            # #1 capture-mode (live-fix 2026-06-03): re-arm break-on-next для
            # СЛЕДУЮЩЕГО нового таргета здесь (на quit), а НЕ после drain. Так
            # каждый новый JOB халтит ровно первую инструкцию (drain применит BP
            # и Continue), без single-step текущего таргета. Reset silent-arm не
            # трогаем — set_break_on_next_statement выставит его заново.
            if self._capture_mode:
                try:
                    await self.set_break_on_next_statement(silent=True)
                    log.info("[capture-mode] re-armed break-on-next on quit (for next target)")
                except Exception as e:
                    log.warning("[capture-mode] re-arm on quit failed: %s", e)

        elif cmd_type == "correctedBP":
            log.warning(
                "[event] BP corrected to adjusted line for target %s", (target_id or "?")[:8]
            )

        elif cmd_type == "exprEvaluated":
            # Async eval result delivery: evalExpr POST queues the evaluation
            # with expressionResultID; the computed value arrives later as this
            # event. Resolve the matching Future in _pending_evals so the caller
            # of eval_expression() unblocks. yukon39 mirror: DBGUIExtCmdInfoExpr-
            # Evaluated event class + ContextServerEventSubscriber dispatch.
            eval_data = cmd.get("evalExprResBaseData") or cmd.get("data") or cmd
            result_id = eval_data.get("expressionResultID") if isinstance(eval_data, dict) else None
            if not result_id:
                # Fallback — scan nested dicts for expressionResultID
                for v in cmd.values():
                    if isinstance(v, dict) and v.get("expressionResultID"):
                        result_id = v["expressionResultID"]
                        eval_data = v
                        break
            if result_id and result_id in self._pending_evals:
                fut = self._pending_evals.pop(result_id)
                if not fut.done():
                    fut.set_result(eval_data)
                log.info("[event] ExprEvaluated: result_id=%s resolved", result_id[:8])
            else:
                log.debug(
                    "[event] ExprEvaluated for unknown result_id=%s (no pending future)",
                    (result_id or "?")[:8],
                )

        elif cmd_type in (
            "ForegroundHelperSet",
            "ForegroundHelperRequest",
            "ForegroundHelperProcess",
            "measureResultProcessing",
            "errorViewInfo",
            "rteOnBPConditionProcessing",
            "valueModified",
            "unknown",
            "",
        ):
            log.debug("[event] Skipping %s", cmd_type or "<empty>")

        else:
            log.debug("[event] Unrecognised cmdId=%r tag=%r", cmd_type, cmd.get("_tag"))

    _UUID_RE = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
    )

    @classmethod
    def _extract_target_id(cls, cmd: dict) -> Optional[str]:
        """Extract target UUID from event payload (reviewer-recommended fix 2026-05-09).

        Payload может содержать:
          - "targetID": {"_tag": "DebugTargetIdStr", "id": "<uuid>"}
          - "targetID": "<uuid>" (flat)
          - "targetIDStr": ...

        Last-resort fallback ОТБРОШЕН — раньше брал первое попавшееся
        non-_tag string, что могло вернуть `requestQueueID` или другой
        non-UUID. Теперь strict UUID-format validation на all paths.
        """
        for key in ("targetID", "targetIDStr"):
            val = cmd.get(key)
            if isinstance(val, str) and cls._UUID_RE.match(val):
                return val
            if isinstance(val, dict):
                # Nested struct — try common id fields, validate UUID format
                for inner_key in ("id", "_value", "uuid"):
                    inner = val.get(inner_key)
                    if isinstance(inner, str) and cls._UUID_RE.match(inner):
                        return inner
        return None

    async def init_settings(self) -> bool:
        """RDBG initSettings — part of Debug UI post-attach handshake.

        yukon39 reference: ServerContext.attach() line 60 creates
        `new HTTPServerInitialDebugSettingsData()` WITHOUT setting any
        fields, then calls `debugee.attach(data)` which routes through
        Debugee.attach() lines 97-109: attach → initSettings → clear-
        BreakOnNextStatement → setAutoAttachSettings.

        With JAXB `XmlAccessType.NONE` + Lombok `@Data`, only the
        default-initialized `inacessibleModuleID = []` field gets
        serialized. Body is essentially `<data/>` (empty, no children).

        Earlier 2026-05-10 attempt sent <bpWorkspace/> + <rteProcessing>
        per RDBGSetInitialDebugSettingsRequestTest.xml fixture — that's a
        TEST fixture, not the production-runtime body. Live RDBG 8.3.27
        accepted the test-body (HTTP 200) but eval still failed with
        «UI+ часть отладки не зарегистрирована». Switching to empty data
        + adding clearBreakOnNextStatement step matches yukon39 production.

        Pre-2026-05-10 (broken): built `breakOnNextLine` + `autoAttach-
        Settings` body for cmd=initSettings — RDBG silently accepted but
        neither initialized UI+ nor set autoAttach. Auto-attach moved to
        dedicated `set_auto_attach_settings`.

        Idempotent at session level — call once per attachDebugUI. After
        detachDebugUI → attachDebugUI cycle, must re-call.
        """
        body = _build_request(
            self._base_fields(),
            _rdbg("data"),
        )
        await self._post("initSettings", body)
        return True

    async def clear_break_on_next_statement(self) -> bool:
        """RDBG clearBreakOnNextStatement — yukon39 attach handshake step 3.

        yukon39 reference: HTTPDebugClient.clearBreakOnNextStatement() lines
        273-283. Body has no payload beyond `_base_fields()`. Called between
        initSettings (step 2) and setAutoAttachSettings (step 4) per Debugee.
        attach() lines 97-109. Without it Debug UI may carry stale break-on-
        next flag from prior session, causing spurious stops.

        Different from `set_break_on_next_statement` (the inverse op which
        ARMS break-on-next as a global cmd).
        """
        body = _build_request(self._base_fields())
        await self._post("clearBreakOnNextStatement", body)
        return True

    async def set_auto_attach_settings(self, target_types: list[str] | None = None) -> bool:
        """RDBG setAutoAttachSettings — declare which target kinds auto-attach.

        Separate cmd from initSettings (yukon39 Debugee.attach() calls them in
        sequence: initSettings → clearBreakOnNextStatement → setAutoAttach-
        Settings). Default subscribes to Server (rphost) + ManagedClient
        (1cv8c.exe) — covers thin-client + server-side rphost session.
        """
        # Roadmap 260511 §P0.5 (2026-05-11): расширенный filter после yukon39 XSD review.
        # `debugAutoAttach.xsd` подтверждает что DebugTargetType enum включает
        # HTTPService, WEBService, JOB, OData, COMConnector — все эти target types
        # spawn'ятся как separate rphost workers ragent'ом для соответствующих
        # session kinds. Закрывает RC2 deeper gap из GKSTCPLK-2468 E2E: до этого
        # filter был `["Server", "ManagedClient"]` → HTTPService rphost'ы (через
        # 1c-mcp-crud:execute_code) пропускались → 0 BP fire.
        #
        # Previous ROLLBACK 2026-05-10 ошибочно интерпретировал HTTP 400 «несоот-
        # ветствие targetType» как XSD invalidation. По yukon39/bsl-debug-server
        # XSD (tools/bsl-debug-server/src/test/resources/xsd/debugBaseData.xsd:105-
        # 123), enum полный: Unknown/Client/ManagedClient/WEBClient/COMConnector/
        # Server/ServerEmulation/WEBService/HTTPService/OData/JOB/JobFileMode/
        # Mobile*. 400 был на typo / case-sensitivity, не XSD violation.
        types = target_types or [
            "Server",
            "ManagedClient",
            "HTTPService",
            "WEBService",
            "JOB",
            "JobFileMode",
            "COMConnector",
            "OData",
        ]
        auto_attach = "".join(_auto("targetType", t) for t in types)
        body = _build_request(
            self._base_fields(),
            _rdbg("autoAttachSettings", auto_attach),
        )
        await self._post("setAutoAttachSettings", body)
        return True

    async def detach(self) -> bool:
        if self._ping_task and not self._ping_task.done():
            self._ping_task.cancel()
        body = _build_request(
            _rdbg("infoBaseAlias", self.infobase_alias),
            _rdbg("idOfDebuggerUI", self.session_id),
        )
        try:
            await self._post("detachDebugUI", body)
            self._attached = False
            self._registered = False
            _clear_active_session()
            return True
        except Exception:
            return False

    async def attach_debug_targets(self, target_uuids: list[str], attach: bool = True) -> bool:
        """Attach/detach specific debug targets to this session."""
        ids = "".join(_rdbg("id", _target_id_light(uid)) for uid in target_uuids)
        body = _build_request(
            self._base_fields(),
            _rdbg("attach", str(attach).lower()),
            ids,
        )
        await self._post("attachDetachDbgTargets", body)
        return True

    async def set_break_on_next_statement(self, silent: bool = False) -> bool:
        """RDBG global op — break on next BSL statement on any eligible target.

        Args:
            silent: P0.G — if True, resulting halt is drained silently (target
                attached + BPs reapplied + Continue), no user-visible stop. Used
                by `debug_arm_next_rphost` for autonomous warm-pool BP fire.

        Closes the gap detected 2026-05-10: pre-existing rphosts (alive before
        debug_connect) are invisible to a fresh debug UI session; getDbgAll-
        TargetStates returns []; targetStarted events never fire for them, so
        BPs registered via set_breakpoints never trigger. yukon39 mirror:
        HTTPDebugClient.setBreakOnNextStatement (Java line 262).

        After this call, the very next BSL statement executed by ANY rphost
        for this infobase causes a stop event; the ping loop then sees a
        callStackFormed event and the wrapper auto-attaches that target via
        the standard handler path. Use cleanup via debug_step("Continue") to
        resume normal execution once a target is captured.
        """
        body = _build_request(self._base_fields())
        await self._post("setBreakOnNextStatement", body)
        if silent:
            self._break_on_next_silent_arm = True  # P0.G: drain halt invisibly
        else:
            self._break_on_next_armed = True  # P0.D: keep next stop visible
        return True

    # -- Observation API ---------------------------------------------------

    async def get_target_state(self, target_uuid: Optional[str] = None) -> dict:
        """Get state of a single debug target.

        Real-world finding 2026-05-09 (RDBG 8.3.27.1936): `getDbgTargetState`
        отвергает запрос без targetID с HTTP 400 «Не указан идентификатор
        предмета отладки». Прежняя yukon39-based гипотеза о session-state
        семантике без targetID не подтверждена на 8.3.27. Поэтому:

        - target_uuid is None → возвращаем wrapper-side session snapshot
          (infobase_alias, session_id, attached, known/stopped targets) без
          HTTP roundtrip. Полезно для диагностики UI session без падения.
        - target_uuid передан → resolve через get_targets() (safe path,
          per-target single-state endpoint имеет undocumented contract).
        """
        if target_uuid is None:
            return {
                "_tag": "session_state",
                "infobase_alias": self.infobase_alias,
                "session_id": self.session_id,
                "attached": self._attached,
                "known_attached_targets": sorted(self._known_attached_targets),
                "stopped_targets": sorted(self._stopped_targets),
                "last_stopped_target_id": self._last_stopped_target_id,
            }
        # Per-target: использовать get_targets() и отфильтровать
        targets = await self.get_targets()
        for t in targets:
            if t.get("id") == target_uuid:
                return t
        return {"_tag": "not_found", "target_uuid": target_uuid}

    async def get_breakpoints(self) -> list[dict]:
        """Return client-side BP cache (yukon39 BreakpointsManager pattern).

        Roadmap §4.4 P2.4 diagnostic. RDBG не expose'ит server-side
        `getBreakpoints` URL command (yukon39 source HTTPDebugClient тоже
        его не вызывает). Мы ведём local cache по каждому successful
        `set_breakpoints` call.
        """
        return list(self._set_breakpoints_cache)

    async def get_targets(self) -> list[dict]:
        """Get all debug target states."""
        body = _build_request(self._base_fields())
        root = await self._post("getDbgAllTargetStates", body)
        targets = []
        for item in root:
            if _strip_ns(item.tag) != "item":
                continue
            t = {}
            for child in item:
                ctag = _strip_ns(child.tag)
                if ctag == "targetID":
                    for sub in child:
                        t[_strip_ns(sub.tag)] = (sub.text or "").strip()
                elif child.text:
                    t[ctag] = child.text.strip()
            targets.append(t)
        return targets

    async def ping(self) -> list[dict]:
        """Ping for events AND dispatch to _handle_command (cache, auto-attach).

        Single source of truth for event processing. Both background
        `_ping_loop` and manual `debug_ping` MCP tool go through this — so
        no matter who drains the RDBG queue, `_last_stack_by_target` /
        `_last_stopped_target_id` / `_known_attached_targets` get populated.

        Pre-fix 2026-05-10 root cause: ping() returned raw events without
        dispatch; only _ping_loop processed them. When user invoked manual
        debug_ping between background ticks, that ping drained the queue
        AND ROBBED _ping_loop of those events — cache stayed empty. The
        next debug_stack_trace then took the HTTP-fallback path (cache
        miss), which could raise httpx errors with empty body and surface
        as opaque MCP failure.

        Post-fix: ping() dispatches inline. _ping_loop just delegates here.
        Per-event try/except prevents one bad event from blocking the rest.
        """
        body = _build_request(
            _rdbg("idOfDebuggerUI", self.session_id),
        )
        root = await self._post("pingDebugUIParams", body, include_dbgui_url=True)
        events = _parse_response(root)
        for ev in events:
            try:
                await self._handle_command(ev)
            except Exception as e:
                tag = ev.get("cmdID") or ev.get("_tag", "?")
                log.warning("ping dispatch failed for %s: %s", str(tag)[:40], e)
        return events

    # -- Post-BP-fire helpers (roadmap §13) --------------------------------

    @property
    def last_stopped_target_id(self) -> Optional[str]:
        """Last target that hit BP / step / exception (set by ping event-loop).

        Public accessor для wrapper'ов и external callers (replaces
        accessing private `_last_stopped_target_id` — reviewer fix 2026-05-09).
        """
        return self._last_stopped_target_id

    def _resolve_target_uuid(self, target_uuid: Optional[str]) -> Optional[str]:
        """Fallback to last stopped target if caller didn't specify.

        Roadmap §13.12 / P1.3: tools без явного target_id (например,
        debug_stack_trace) подхватывают последний stopped target из
        ping event-loop'а, а не делают get_targets pull (который может
        lag за несколько секунд).
        """
        if target_uuid:
            return target_uuid
        return self._last_stopped_target_id

    async def _ensure_target_attached(self, target_uuid: str) -> None:
        """Idempotent attach перед eval/step (roadmap §13 P1.2 race-window).

        Если ping event-loop уже attached target — это NO-OP (по факту
        повторный POST attachDetachDbgTargets, который RDBG accepts).
        Защищает tools от race window: ping взялся каждые 2с, а tool
        вызывается через 0.1с после BP-fire — без этой страховки RDBG
        вернёт 400 «Предмет отладки не зарегистрирован».
        """
        if not target_uuid:
            return
        if target_uuid in self._known_attached_targets:
            return  # already attached via ping event
        try:
            await self.attach_debug_targets([target_uuid])
            self._known_attached_targets.add(target_uuid)
            log.debug("[ensure_attached] target %s attached on demand", target_uuid[:8])
        except Exception as e:
            log.warning("[ensure_attached] %s failed: %s", target_uuid[:8], e)

    async def get_call_stack(self, target_uuid: Optional[str] = None) -> list[dict]:
        """Get call stack. Roadmap §13: prefer cached stack from ping events.

        yukon39 pattern: stack arrives push в DBGUIExtCmdInfoCallStackFormed.
        Сначала проверяем cache, fallback на pull-request только если miss.
        """
        target_uuid = self._resolve_target_uuid(target_uuid)
        if not target_uuid:
            log.warning("get_call_stack: no target_uuid and no last_stopped")
            return []

        # Cached push-stack (preferred path)
        cached = self._last_stack_by_target.get(target_uuid)
        if cached:
            log.debug(
                "[get_call_stack] cache hit target=%s frames=%d", target_uuid[:8], len(cached)
            )
            return cached

        # Pull fallback — может вернуть 400 если target не attached
        await self._ensure_target_attached(target_uuid)
        body = _build_request(
            self._base_fields(),
            _rdbg("id", _target_id_light(target_uuid)),
        )
        root = await self._post("getCallStack", body)
        stack = []
        for item in root:
            if _strip_ns(item.tag) == "callStack":
                stack.append(_parse_element(item))
        return stack

    # -- Evaluation API ----------------------------------------------------

    async def eval_local_variables(
        self,
        target_uuid: Optional[str] = None,
        stack_level: int = 0,
        expressions: Optional[list[str]] = None,
        async_wait_timeout: float = 10.0,
        max_text_size: int = 4096,
    ) -> list[dict]:
        """Evaluate named local variables via batch evalLocalVariables.

        yukon39 RDBGEvalLocalVariablesRequest takes a list of `Calculation-
        SourceDataStorage` — caller provides explicit variable names. RDBG has
        NO "dump all locals" call; passing empty list returns nothing.

        2026-05-10 fix: requires non-empty `expressions`. For auto-discovery
        from BSL source see `eval_locals_auto()`.
        """
        target_uuid = self._resolve_target_uuid(target_uuid)
        if not target_uuid:
            raise ValueError("eval_local_variables: no target_uuid and no last_stopped")
        if not expressions:
            return []
        await self._ensure_target_attached(target_uuid)
        # Build one <expr> block per name. Each gets unique expressionResultID
        # for async pickup via _pending_evals + exprEvaluated event.
        expr_blocks: list[str] = []
        result_ids: list[tuple[str, str, asyncio.Future]] = []
        loop = asyncio.get_event_loop()
        for name in expressions:
            result_id = str(uuid.uuid4())
            fut: asyncio.Future = loop.create_future()
            self._pending_evals[result_id] = fut
            result_ids.append((name, result_id, fut))
            src_calc_info = _calc("expressionResultID", result_id) + _calc(
                "calcItem", _calc("itemType", "expression") + _calc("expression", name)
            )
            expr_blocks.append(
                _rdbg(
                    "expr",
                    _calc("stackLevel", str(stack_level))
                    + _calc("srcCalcInfo", src_calc_info)
                    + _calc("presOptions", _calc("maxTextSize", str(max_text_size))),
                )
            )
        body = _build_request(
            self._base_fields(),
            _rdbg("calcWaitingTime", "3"),
            _rdbg("targetID", _target_id_light(target_uuid)),
            *expr_blocks,
        )
        try:
            root = await self._post("evalLocalVariables", body)
            sync_results = _parse_response(root)
            sync_by_id: dict[str, dict] = {}
            for item in sync_results:
                rid = item.get("expressionResultID")
                if rid:
                    sync_by_id[rid] = item
            out: list[dict] = []
            for name, result_id, fut in result_ids:
                if result_id in sync_by_id:
                    self._pending_evals.pop(result_id, None)
                    out.append({"name": name, **sync_by_id[result_id]})
                    continue
                if async_wait_timeout <= 0:
                    out.append({"name": name, "evalResultState": "pending"})
                    continue
                try:
                    eval_data = await asyncio.wait_for(fut, timeout=async_wait_timeout)
                    out.append({"name": name, **(eval_data or {})})
                except asyncio.TimeoutError:
                    log.warning(
                        "eval_local_variables[%s] timeout after %ss", name, async_wait_timeout
                    )
                    out.append({"name": name, "evalResultState": "timeout"})
            return out
        finally:
            for _, result_id, _ in result_ids:
                self._pending_evals.pop(result_id, None)

    async def eval_locals_auto(
        self,
        target_uuid: Optional[str] = None,
        stack_level: int = 0,
        async_wait_timeout: float = 10.0,
        max_text_size: int = 4096,
    ) -> list[dict]:
        """Auto-discover local names from BSL source then evaluate them.

        Pipeline:
        1. Get current stack frame (last_stopped + stack_level)
        2. Resolve frame's UUID → BSL file path via uuid_index
        3. Parse with bsl_locals.extract_locals_at_line()
        4. Pass extracted names to eval_local_variables
        """
        target_uuid = self._resolve_target_uuid(target_uuid)
        if not target_uuid:
            return []
        cached_stack = self._last_stack_by_target.get(target_uuid)
        if not cached_stack or stack_level >= len(cached_stack):
            return []
        frame = cached_stack[stack_level]
        module_id = frame.get("moduleID") or {}
        if not isinstance(module_id, dict):
            return []
        object_id = module_id.get("objectID")
        property_id = module_id.get("propertyID")
        line_no_raw = frame.get("lineNo")
        if not (object_id and property_id and line_no_raw):
            return []
        try:
            line_no = int(line_no_raw)
        except (TypeError, ValueError):
            return []
        path = uuid_index.resolve_uuid(object_id, property_id)
        if path is None or not path.exists():
            log.info(
                "eval_locals_auto: UUID %s + %s -> no source path", object_id[:8], property_id[:8]
            )
            return []
        names = bsl_locals.extract_locals_at_line(path, line_no)
        if not names:
            log.info("eval_locals_auto: no locals extracted at %s:%d", path.name, line_no)
            return []
        log.info("eval_locals_auto: extracted %d names at %s:%d", len(names), path.name, line_no)
        return await self.eval_local_variables(
            target_uuid=target_uuid,
            stack_level=stack_level,
            expressions=names,
            async_wait_timeout=async_wait_timeout,
            max_text_size=max_text_size,
        )

    async def eval_expression(
        self,
        expression: str,
        target_uuid: Optional[str] = None,
        stack_level: int = 0,
        view_interface: Optional[str] = None,
        max_text_size: int = 4096,
        async_wait_timeout: float = 10.0,
    ) -> list[dict]:
        """Evaluate a specific BSL expression at a breakpoint.

        Roadmap §13 P1.2: idempotent re-attach + fallback на last_stopped.
        Note: signature reordered — `expression` теперь первый positional
        param, `target_uuid` опциональный (defaults to last stopped).

        Args:
            expression: BSL выражение
            target_uuid: explicit target или None (fallback на last_stopped)
            stack_level: 0 = текущий кадр
            view_interface: §4.3 P2.3 — opt-in tag для composite types
                (СправочникСсылка/ДокументСсылка/Структура). Передаётся
                в presOptions.viewInterface; платформа форматирует значение
                согласно interface (например "context" для programmer-view).
                Default None = используем default presentation.
            max_text_size: Максимум char для текстового представления
                (default 4096; для очень больших таблиц поднимайте до 16384).
        """
        target_uuid = self._resolve_target_uuid(target_uuid)
        if not target_uuid:
            raise ValueError("eval_expression: no target_uuid and no last_stopped")
        await self._ensure_target_attached(target_uuid)
        # §12.3 Level 3 metrics
        self._eval_count += 1
        expr_result_id = str(uuid.uuid4())
        # Pre-register Future BEFORE POST — async event may arrive before
        # the POST response if RDBG is fast enough; ping_loop must find a
        # waiting future so the result isn't dropped.
        loop = asyncio.get_event_loop()
        pending_fut: asyncio.Future = loop.create_future()
        self._pending_evals[expr_result_id] = pending_fut
        src_calc_info = _calc("expressionResultID", expr_result_id) + _calc(
            "calcItem", _calc("itemType", "expression") + _calc("expression", expression)
        )
        pres_options_xml = _calc("maxTextSize", str(max_text_size))
        if view_interface:
            pres_options_xml += _calc("viewInterface", view_interface)
        expr_xml = (
            _calc("stackLevel", str(stack_level))
            + _calc("srcCalcInfo", src_calc_info)
            + _calc("presOptions", pres_options_xml)
        )
        body = _build_request(
            self._base_fields(),
            _rdbg("calcWaitingTime", "3"),
            _rdbg("targetID", _target_id_light(target_uuid)),
            _rdbg("expr", expr_xml),
        )
        try:
            root = await self._post("evalExpr", body)
            sync_result = _parse_response(root)
            # If RDBG returned the value inline (calcWaitingTime sufficed),
            # the response is non-empty — return immediately and discard future.
            if sync_result:
                self._pending_evals.pop(expr_result_id, None)
                return sync_result
            # Otherwise wait for `exprEvaluated` event from ping_loop.
            # Timeout = calcWaitingTime + ping interval (2s) + slack.
            # Set async_wait_timeout=0 to skip wait entirely (returns []
            # if sync_result was empty — useful for unit tests that don't
            # exercise the ping_loop event path).
            if async_wait_timeout <= 0:
                return []
            try:
                eval_data = await asyncio.wait_for(pending_fut, timeout=async_wait_timeout)
                return [eval_data] if eval_data else []
            except asyncio.TimeoutError:
                log.warning(
                    "eval_expression timeout for result_id=%s — RDBG didn't deliver "
                    "exprEvaluated event within %ss",
                    expr_result_id[:8],
                    async_wait_timeout,
                )
                return []
        finally:
            self._pending_evals.pop(expr_result_id, None)

    # -- Control API -------------------------------------------------------

    async def step(self, action: str = "Continue", target_uuid: Optional[str] = None) -> list[dict]:
        """Step execution. Actions: Continue, Step, StepIn, StepOut.

        Roadmap §13 P1.2 + P2.2 Continue resume semantic:
          1. Resolve target_uuid (fallback to last_stopped_target_id)
          2. Idempotent re-attach
          3. Send step action
          4. Drop target из _stopped_targets (running again)
        Note: signature reordered — `action` первый, `target_uuid` опциональный.
        """
        target_uuid = self._resolve_target_uuid(target_uuid)
        if not target_uuid:
            raise ValueError("step: no target_uuid and no last_stopped")
        await self._ensure_target_attached(target_uuid)
        body = _build_request(
            self._base_fields(),
            _rdbg("targetID", _target_id_light(target_uuid)),
            _rdbg("action", action),
        )
        root = await self._post("step", body)
        # After step, target is running — drop from stopped set.
        # Next CallStackFormed/RTE event will re-add it if hit again.
        # Reviewer fix 2026-05-09: also clear stale exception cache so
        # subsequent step.Continue from RTE doesn't see ghost exception.
        self._stopped_targets.discard(target_uuid)
        self._last_exception_by_target.pop(target_uuid, None)
        if self._last_stopped_target_id == target_uuid:
            self._last_stopped_target_id = None
        return _parse_response(root)

    # -- Breakpoints API -----------------------------------------------------

    async def _reapply_bp_workspace(self) -> None:
        """Re-apply cached BP workspace to RDBG. Roadmap 260511 §P0.5.

        Used by `_handle_command(targetStarted)` для гарантии что свежий
        target (JOB / HTTPService / etc) получит BPs ДО первой BSL операции.
        Short-lived JOB targets (execute_code via 1c-mcp-crud) могут
        spawn → execute → quit за <100ms; без re-apply BPs не push'ятся
        вовремя и BP не fire.

        Идемпотентно: если cache пуст — noop. Полный workspace отправляется
        одним setBreakpoints request'ом. **RDBG `setBreakpoints` REPLACES
        workspace per call** (Fix #5 / live finding 2026-05-10) — повторный
        push того же state идempotent на RDBG-side.

        Race note: multiple targets started simultaneously → N parallel
        calls. Поскольку RDBG REPLACES, последний wins; intermediate
        излишни, но НЕ вредны (correctness preserved, ~N HTTP cost).
        """
        if not self._set_breakpoints_cache:
            return
        module_bp_infos: list = []
        for entry in self._set_breakpoints_cache:
            mod_xml = (
                _base("type", entry["module_type"])
                + _base("objectID", entry["object_id"])
                + _base("propertyID", entry["property_id"])
            )
            if entry.get("url"):
                mod_xml += _base("url", entry["url"])
            if entry.get("extension_name"):
                mod_xml += _base("extensionName", entry["extension_name"])
            if entry.get("ext_id"):
                mod_xml += _base("extId", str(entry["ext_id"]))
            if entry.get("version"):
                mod_xml += _base("version", entry["version"])
            # Preserve per-entry condition on re-apply (review PR#1 #2): use the
            # shared _build_bp_info_xml helper so conditional BPs do not silently
            # revert to unconditional during targetStarted / HMR-recovery re-apply.
            bp_xml = "".join(
                _build_bp_info_xml(L, entry.get("condition", "")) for L in entry["lines"]
            )
            module_bp_infos.append(_bp("moduleBPInfo", _bp("id", mod_xml) + bp_xml))
        workspace_xml = _rdbg("bpWorkspace", "".join(module_bp_infos))
        body = _build_request(self._base_fields(), workspace_xml)
        await self._post("setBreakpoints", body)

    def _record_hit_condition(self, object_id, property_id, lines, hit_condition):
        """P0.A: register hit-condition per (oid, pid, line)."""
        for ln in lines:
            key = (object_id, property_id, int(ln))
            self._hit_conditions[key] = hit_condition
            self._hit_counters.setdefault(key, 0)

    def _record_logpoint(self, object_id, property_id, lines, template):
        """P0.B: register logpoint template per (oid, pid, line)."""
        for ln in lines:
            key = (object_id, property_id, int(ln))
            self._logpoints[key] = template

    async def set_breakpoints(
        self,
        module_type: str,
        object_id: str,
        property_id: str,
        lines: list[int],
        ext_id: int = 0,
        url: str = "",
        extension_name: str = "",
        version: str = "",
        condition: str = "",
        hit_condition: str = "",
        logpoint_template: str = "",
    ) -> list[dict]:
        """Set breakpoints on specific lines in a BSL module.

        Args:
            module_type: BSLModuleType — ExtMDModule (form), ConfigModule, etc.
            object_id: UUID of the metadata object (e.g. DataProcessor).
            property_id: UUID of the form/module.
            lines: List of line numbers to set breakpoints on.
            ext_id: Extension ID (default 0).
            url: Module URL (usually empty).
            extension_name: Extension name (usually empty).
            version: Config version. Roadmap §6.1: RDBG может silently
                дропать BPs если version не совпадает с running configVersion.
                Empty (default) обычно works для standard configs; передавайте
                для extensions.
        """
        # Fix #5 (live finding 2026-05-10): RDBG setBreakpoints REPLACES the
        # workspace each call. Aggregating cache + new entry → submit FULL
        # workspace XML с multiple moduleBPInfo, иначе предыдущие BPs теряются.
        new_entry = {
            "module_type": module_type,
            "object_id": object_id,
            "property_id": property_id,
            "lines": list(lines),
            "ext_id": ext_id,
            "url": url,
            "extension_name": extension_name,
            "version": version,
            "condition": condition or "",
        }
        if hit_condition:
            self._record_hit_condition(object_id, property_id, lines, hit_condition)
        if logpoint_template:
            self._record_logpoint(object_id, property_id, lines, logpoint_template)
        groups = _aggregate_breakpoints(self._set_breakpoints_cache, new_entry)
        module_bp_infos: list = []
        for (mt, oid, pid, eid, url_, ext_, ver_), bp_lines in groups.items():
            mod_xml = _base("type", mt) + _base("objectID", oid) + _base("propertyID", pid)
            if url_:
                mod_xml += _base("url", url_)
            if ext_:
                mod_xml += _base("extensionName", ext_)
            if eid:
                mod_xml += _base("extId", str(eid))
            if ver_:
                mod_xml += _base("version", ver_)
            bp_xml = "".join(_build_bp_info_xml(L, cond) for L, cond in bp_lines.items())
            module_bp_infos.append(_bp("moduleBPInfo", _bp("id", mod_xml) + bp_xml))
        workspace_xml = _rdbg("bpWorkspace", "".join(module_bp_infos))
        body = _build_request(self._base_fields(), workspace_xml)
        root = await self._post("setBreakpoints", body)
        # Reconcile cache from groups (consolidates duplicate entries и
        # сохраняет full state для следующего set call).
        self._set_breakpoints_cache = [
            {
                "module_type": k[0],
                "object_id": k[1],
                "property_id": k[2],
                "ext_id": k[3],
                "url": k[4],
                "extension_name": k[5],
                "version": k[6],
                "lines": list(v.keys()),
                "condition": next(iter(v.values()), "") if v else "",
            }
            for k, v in groups.items()
        ]
        return _parse_response(root)

    async def close(self):
        if self._attached:
            await self.detach()
        await self._http.aclose()


# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------
_client: Optional[RDBGClient] = None


def _get_client() -> RDBGClient:
    """Return the singleton RDBGClient, restoring HMR-saved state on cold start.

    §13.x: when mcp_hmr_proc.py respawns this subprocess on source-file change,
    in-memory state is gone but RDBG still has our session registered (60s GC
    grace). _load_active_session() recovers session_id + connection params,
    so the very first MCP call after restart hits RDBG with the SAME dbgui id
    and avoids the «UI+ - часть отладки не зарегистрирована» 400 round-trip.

    If the persisted session is stale (RDBG GC'd it, dbgs.exe rebooted), the
    existing _ui_plus_recover_and_retry path escalates to a full re-attach on
    the first failing call — and the new session_id is then re-persisted by
    attach() for future restarts.
    """
    global _client
    if _client is None:
        state = _load_active_session()
        if state and state.get("session_id"):
            _client = RDBGClient(
                debug_url=state.get("debug_url", "http://localhost:1550"),
                infobase_alias=state.get("infobase_alias", "DefAlias"),
            )
            _client.session_id = state["session_id"]
            _client._attached = True
            _client._registered = True
            # B2 §7.5: restore per-module line offsets (measured by calibrate).
            lo = state.get("line_offsets")
            if isinstance(lo, dict):
                _client._line_offsets = {k: int(v) for k, v in lo.items()}
            try:
                # FastMCP tool handlers run inside an active event loop, so
                # asyncio.get_running_loop() succeeds here. RuntimeError only
                # fires если _get_client() is invoked from sync context (CLI
                # mode, или sync unit-tests). Probe the loop FIRST — иначе
                # coroutine creation leaks an unawaited task on RuntimeError.
                loop = asyncio.get_running_loop()
                if _client._ping_task is None or _client._ping_task.done():
                    _client._ping_task = loop.create_task(_client._ping_loop())
            except RuntimeError:
                pass
            log.info(
                "[hmr-restore] active session restored: sid=%s alias=%s (persisted %.0fs ago)",
                state["session_id"][:8],
                state.get("infobase_alias", "?"),
                _time.time() - state.get("persisted_at", _time.time()),
            )
        else:
            _client = RDBGClient()
    return _client


def _find_stopped_target(targets: list[dict]) -> Optional[str]:
    """Find UUID of a stopped target (StopOnNextLine state)."""
    for t in targets:
        state = t.get("state", "")
        if state in ("stopped", "Stopped", "StopOnNextLine", "breakOnNextStatement"):
            tid = t.get("id", "")
            if tid:
                return tid
    return None


async def _resolve_stopped_target(
    client: "RDBGClient",
    target_id: str = "",
) -> tuple[str, Optional[list]]:
    """Resolve target UUID for inspection tools.

    Chain (unchanged behavior): explicit `target_id` → cached
    `last_stopped_target_id` → scan `get_targets()` for a stopped target.

    Returns (target_id, scanned_targets). `scanned_targets` is the list from
    `get_targets()` when a scan happened (so callers can surface it in a
    no-stopped-target error envelope, как делал debug_stack_trace), иначе None.
    Returns ("", targets) when a scan happened but found nothing stopped.

    W1.0.2 (2026-07-08): dedup of identical resolve blocks previously inline in
    debug_stack_trace / debug_variables / debug_evaluate / debug_step.
    """
    if target_id:
        return target_id, None
    target_id = client.last_stopped_target_id or ""
    if target_id:
        return target_id, None
    targets = await client.get_targets()
    return (_find_stopped_target(targets) or ""), targets


def _enrich_stack(stack: list) -> list:
    """Enrich each stack frame with `resolved_source` (FQN + file path).

    P0.C roadmap 260511: resolve frame moduleID (objectID/propertyID UUIDs) →
    `{fqn, file_path, exists}` via uuid_index. Frames without a resolvable
    module pass through unchanged.

    W1.0.3 (2026-07-08): extracted from debug_stack_trace inline loop for reuse
    by debug_inspect_frame (A0).
    """
    enriched = []
    for frame in stack:
        if isinstance(frame, dict):
            mod = frame.get("moduleID") if isinstance(frame.get("moduleID"), dict) else {}
            info = uuid_index.get_source_info(
                mod.get("objectID", ""),
                mod.get("propertyID", ""),
            )
            if info:
                frame = dict(frame)
                frame["resolved_source"] = info
        enriched.append(frame)
    return enriched


def _rdbg_error_text(exc: Exception, limit: int = 400) -> str:
    """Clean, concise message from an exception, stripping RDBG's verbose XML.

    RDBG 4xx errors embed the human-readable reason inside a <descr> element
    wrapped in a large XML/stylesheet preamble (e.g. «Выполнение вычислений
    возможно только в остановленном предмете отладки»). For graceful error
    envelopes (debug_evaluate / debug_variables) we extract just that descr so
    the result is actionable rather than dumping the whole XML document.
    """
    text = str(exc)
    m = re.search(r"<descr[^>]*>(.*?)</descr>", text, re.DOTALL)
    if m:
        return re.sub(r"\s+", " ", m.group(1)).strip()
    return text if len(text) <= limit else text[:limit] + "…"


def _error_json(message: str, error_type: str = "error", **extra) -> str:
    """Единый error-envelope для inspection-tools (stack_trace/variables/evaluate).

    Все ошибочные выходы этих tool'ов имеют одинаковую форму: `error` (текст),
    `error_type` (машинно-читаемый разряд: "not_connected" / "no_stopped_target"
    / имя класса исключения) + контекстные поля через `extra` (target_id,
    expression, ...). Это позволяет вызывающему различать причины программно.
    """
    # Reserved-ключи приоритетны: extra не может перетереть error/error_type
    # (защита от TypeError «multiple values» при будущем неосторожном вызове).
    extra.pop("error", None)
    extra.pop("error_type", None)
    return json.dumps(
        {"error": message, "error_type": error_type, **extra}, ensure_ascii=False, indent=2
    )


# ---------------------------------------------------------------------------
# Roadmap §11 (Solutions A/B): pre-existing rphost detection + force-recycle
# ---------------------------------------------------------------------------
# RDBG protocol contract: setAutoAttachSettings filter применяется только к
# rphost'ам, регистрирующимся ПОСЛЕ её установки. Pre-existing rphost'ы
# (alive до attachDebugUI) невидимы; DBGUIExtCmdInfoStarted event не
# replay'ится для них. Empirically validated 2026-05-10 (roadmap §0).
# Эти helpers закрывают gap на OS-уровне.


def detect_pre_existing_rphosts() -> list[dict]:
    """Detect rphost.exe worker processes on local Windows machine.

    Used by debug_connect() для surfacing «pre-existing rphost invisible» gap
    (§10) — RDBG не attach'ит retroactively уже работающие rphost'ы.

    Returns: list of {pid: int, name: str}; empty list on non-Windows
    или если tasklist.exe недоступен (graceful — не blocking).
    """
    if sys.platform != "win32":
        return []
    try:
        result = subprocess.run(
            ["tasklist.exe", "/FI", "IMAGENAME eq rphost.exe", "/FO", "CSV", "/NH"],
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (subprocess.SubprocessError, OSError, FileNotFoundError):
        return []
    if result.returncode != 0:
        return []
    rphosts: list[dict] = []
    for line in result.stdout.strip().splitlines():
        # tasklist returns `INFO: No tasks are running ...` when none match
        if "INFO:" in line.upper():
            continue
        # CSV-формат /NH: "rphost.exe","12345","Services","0","123 K"
        parts = [p.strip().strip('"') for p in line.split('","')]
        if len(parts) >= 2:
            try:
                rphosts.append({"pid": int(parts[1]), "name": parts[0]})
            except ValueError:
                continue
    return rphosts


_RAC_BIN_CANDIDATES = (
    r"C:\Program Files (x86)\1cv8\8.3.27.1936\bin\rac.exe",
    r"C:\Program Files\1cv8\8.3.27.1936\bin\rac.exe",
    r"C:\Program Files (x86)\1cv8\common\rac.exe",
)

_1CV8C_BIN_CANDIDATES = (
    r"C:\Program Files (x86)\1cv8\8.3.27.1936\bin\1cv8c.exe",
    r"C:\Program Files\1cv8\8.3.27.1936\bin\1cv8c.exe",
)


def _find_rac_exe() -> Optional[str]:
    """Locate rac.exe (1С Remote Administrative Client) on disk."""
    import os

    for path in _RAC_BIN_CANDIDATES:
        if os.path.isfile(path):
            return path
    return None


def _find_1cv8c_exe() -> Optional[str]:
    """Locate 1cv8c.exe (1С thin client) on disk. Roadmap 260511 §3.5 (P1).

    Tries hardcoded paths first; falls back to WMI-style globbing if needed.
    """
    import os
    import glob

    for path in _1CV8C_BIN_CANDIDATES:
        if os.path.isfile(path):
            return path
    # Fallback: glob through `C:\Program Files*\1cv8\*\bin\1cv8c.exe`
    for prefix in (r"C:\Program Files (x86)\1cv8", r"C:\Program Files\1cv8"):
        for found in glob.glob(os.path.join(prefix, "*", "bin", "1cv8c.exe")):
            return found
    return None


def _rac_auth_args() -> list:
    """Build rac auth CLI args from RAC_CLUSTER_USER/RAC_CLUSTER_PWD env.

    Required для cluster security-level≠0 (когда требуется cluster admin
    auth для process operations). Empty list когда env не задано —
    backward compat с security-level=0 (default localhost).
    """
    import os

    args: list = []
    user = os.environ.get("RAC_CLUSTER_USER", "").strip()
    pwd = os.environ.get("RAC_CLUSTER_PWD", "")
    if user:
        args.append(f"--cluster-user={user}")
    if pwd:
        args.append(f"--cluster-pwd={pwd}")
    return args


def force_recycle_rphost_processes(pids: list[int], dry_run: bool = False) -> dict:
    """Recycle rphost.exe workers via rac (graceful) или taskkill fallback.

    Live validation 2026-05-10: SYSTEM-owned rphost (запущен под service
    account) НЕ kill'ится через non-elevated `taskkill /F` — Access Denied.
    `rac process turn-off` работает БЕЗ admin elevation на cluster
    security-level=0 (default для localhost) и graceful'но drain'ит активные
    сессии другому worker'у. Если rac.exe не найден — fallback на taskkill.

    Returns: {killed, failed: [{pid, error}], method: "rac.turn_off"|"taskkill"|"noop"}.
    """
    if sys.platform != "win32" or not pids:
        return {"killed": [], "failed": [], "method": "noop"}
    # Fix #4 §12.8: dry_run mode — preview без destructive ops
    if dry_run:
        return {
            "killed": [],
            "failed": [],
            "method": "dry_run",
            "would_kill": list(pids),
            "note": "dry_run=True — no subprocess invoked",
        }
    # Path 1 — rac (graceful, no admin, only if rac.exe available + cluster reachable)
    rac_exe = _find_rac_exe()
    if rac_exe:
        cluster = _rac_get_cluster_uuid(rac_exe)
        if cluster:
            pid_to_uuid = _rac_list_processes_by_pid(rac_exe, cluster)
            return _recycle_via_rac(rac_exe, cluster, pids, pid_to_uuid)
    # Path 2 — full service restart (kills ALL rphosts; gated by env opt-in
    # т.к. invasive — обрывает чужие user sessions). Требует SDDL grant
    # (scripts/grant-1c-debug-permissions.ps1) или admin elevation.
    import os

    if os.environ.get("BSL_DEBUG_ALLOW_SERVICE_RESTART", "").lower() == "true":
        return _recycle_via_service(pids)
    # Path 3 — taskkill fallback (Access Denied для SYSTEM-owned rphost)
    return _recycle_via_taskkill(pids)


def _rac_get_cluster_uuid(rac_exe: str) -> Optional[str]:
    """Run `rac cluster list`, parse first cluster UUID."""
    try:
        result = subprocess.run(
            [rac_exe, "cluster", "list"],
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (subprocess.SubprocessError, OSError):
        return None
    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        if line.strip().startswith("cluster"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                u = parts[1].strip()
                if len(u) >= 32 and "-" in u:
                    return u
    return None


def _rac_list_processes_by_pid(rac_exe: str, cluster: str) -> dict:
    """Map OS pid → cluster process UUID via `rac process list`."""
    try:
        result = subprocess.run(
            [rac_exe, "process", "list", f"--cluster={cluster}", *_rac_auth_args()],
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (subprocess.SubprocessError, OSError):
        return {}
    if result.returncode != 0:
        return {}
    pid_to_uuid: dict = {}
    current_uuid: Optional[str] = None
    for raw in result.stdout.splitlines():
        line = raw.strip()
        if line.startswith("process"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                u = parts[1].strip()
                current_uuid = u if (len(u) >= 32 and "-" in u) else None
        elif line.startswith("pid") and current_uuid:
            parts = line.split(":", 1)
            if len(parts) == 2:
                try:
                    pid_to_uuid[int(parts[1].strip())] = current_uuid
                except ValueError:
                    pass
    return pid_to_uuid


def _rac_list_infobases(rac_exe: str, cluster: str) -> list[dict]:
    """Run `rac infobase summary list --cluster=<UUID>`, parse {uuid, name} pairs.

    Returns: list[{"uuid": "...", "name": "..."}] — empty list если cluster
    unreachable / rac fails. Used by _validate_infobase_alias и
    _rac_list_rphosts_of_infobase (recycle_strategy=all_rphosts_of_ib).
    """
    try:
        result = subprocess.run(
            [rac_exe, "infobase", f"--cluster={cluster}", "summary", "list", *_rac_auth_args()],
            capture_output=True,
            text=True,
            timeout=5,
            encoding="cp866",
            errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (subprocess.SubprocessError, OSError):
        return []
    if result.returncode != 0:
        return []
    infobases: list[dict] = []
    current_uuid: Optional[str] = None
    current_name: Optional[str] = None
    for raw in result.stdout.splitlines():
        line = raw.strip()
        if line.startswith("infobase"):
            if current_uuid and current_name:
                infobases.append({"uuid": current_uuid, "name": current_name})
            current_uuid = None
            current_name = None
            parts = line.split(":", 1)
            if len(parts) == 2:
                u = parts[1].strip()
                if len(u) >= 32 and "-" in u:
                    current_uuid = u
        elif line.startswith("name"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                current_name = parts[1].strip()
    if current_uuid and current_name:
        infobases.append({"uuid": current_uuid, "name": current_name})
    return infobases


def _resolve_alias_from_env(alias: str) -> str:
    """Resolve short alias from DEBUG_INFOBASE_ALIASES env mapping.

    Roadmap 260511 §3.7 (P2). Env format: "Short:Long;Short2:Long2".

    Example: DEBUG_INFOBASE_ALIASES="TestDB:ИБTransportManagementDevelop;Dev:260507_DEV_ATERLETSKIY_53196"

    Returns: resolved long-form alias, or original if no mapping.
    """
    import os

    raw = os.environ.get("DEBUG_INFOBASE_ALIASES", "")
    if not raw:
        return alias
    for entry in raw.split(";"):
        entry = entry.strip()
        if not entry or ":" not in entry:
            continue
        short, long_name = entry.split(":", 1)
        if short.strip() == alias:
            return long_name.strip()
    return alias


def _validate_infobase_alias(alias: str) -> dict:
    """Cross-check infobase_alias против реального cluster IB list.

    Returns dict с одним из трёх состояний:
    - {"status": "valid", "uuid": "<UUID>", "name": alias} — alias найден
    - {"status": "invalid", "available": [<names>]} — alias НЕ найден
    - {"status": "skipped", "reason": "<rac_exe_not_found|cluster_unreachable
       |empty_infobase_list>"} — validation невозможна (graceful degradation,
       НЕ блокирует connect)

    Roadmap 260511 §3.1 (P0) + §3.7 (P2, env alias mapping).
    Closes RC1 из GKSTCPLK-2468 incident.
    """
    # §3.7: resolve через env mapping ДО валидации (short → long)
    resolved_alias = _resolve_alias_from_env(alias)
    rac_exe = _find_rac_exe()
    if not rac_exe:
        return {
            "status": "skipped",
            "reason": "rac_exe_not_found",
            "resolved_alias": resolved_alias,
        }
    cluster = _rac_get_cluster_uuid(rac_exe)
    if not cluster:
        return {
            "status": "skipped",
            "reason": "cluster_unreachable",
            "resolved_alias": resolved_alias,
        }
    infobases = _rac_list_infobases(rac_exe, cluster)
    if not infobases:
        return {
            "status": "skipped",
            "reason": "empty_infobase_list",
            "resolved_alias": resolved_alias,
        }
    for ib in infobases:
        if ib["name"] == resolved_alias:
            return {
                "status": "valid",
                "uuid": ib["uuid"],
                "name": resolved_alias,
                "alias_resolved_from_env": (alias != resolved_alias),
            }
    return {
        "status": "invalid",
        "provided": alias,
        "resolved_alias": resolved_alias,
        "available": [ib["name"] for ib in infobases],
    }


def _rac_list_rphosts_of_infobase(rac_exe: str, cluster: str, infobase_uuid: str) -> list[int]:
    """List rphost OS pids serving the given infobase UUID.

    Used by recycle_strategy=all_rphosts_of_ib (roadmap 260511 §3.2 P0).

    Encoding: cp866 для consistency с _rac_list_infobases — защита от
    UnicodeDecodeError при exotic Windows locales (даже если этот парсер
    смотрит только числовые pids, defensive symmetry дешевле чем silent
    SubprocessError → пустой list).
    """
    try:
        result = subprocess.run(
            [
                rac_exe,
                "process",
                "list",
                f"--cluster={cluster}",
                f"--infobase={infobase_uuid}",
                *_rac_auth_args(),
            ],
            capture_output=True,
            text=True,
            timeout=5,
            encoding="cp866",
            errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (subprocess.SubprocessError, OSError):
        return []
    if result.returncode != 0:
        return []
    pids: list[int] = []
    for raw in result.stdout.splitlines():
        line = raw.strip()
        if line.startswith("pid"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                try:
                    pids.append(int(parts[1].strip()))
                except ValueError:
                    pass
    return pids


def _recycle_via_rac(rac_exe: str, cluster: str, pids: list, pid_to_uuid: dict) -> dict:
    """Turn off rphost workers через `rac process turn-off` (graceful drain)."""
    killed: list = []
    failed: list = []
    for pid in pids:
        proc_uuid = pid_to_uuid.get(pid)
        if not proc_uuid:
            failed.append({"pid": pid, "error": "no cluster process UUID for this PID"})
            continue
        try:
            result = subprocess.run(
                [
                    rac_exe,
                    "process",
                    "turn-off",
                    f"--cluster={cluster}",
                    f"--process={proc_uuid}",
                    *_rac_auth_args(),
                ],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if result.returncode == 0:
                killed.append(pid)
            else:
                err = (result.stderr or result.stdout or "").strip()
                failed.append({"pid": pid, "error": err or f"rac exit={result.returncode}"})
        except (subprocess.SubprocessError, OSError) as e:
            failed.append({"pid": pid, "error": str(e)})
    return {"killed": killed, "failed": failed, "method": "rac.turn_off"}


def _recycle_via_service(pids: list) -> dict:
    """Restart entire 1С service (kills ALL rphosts at once).

    Requires: (1) admin elevation, OR (2) one-time SDDL grant via
    `scripts/grant-1c-debug-permissions.ps1` которое выдаёт Authenticated
    Users право Start/Stop сервиса. После grant `Restart-Service` работает
    БЕЗ UAC. Опционально gated env `BSL_DEBUG_ALLOW_SERVICE_RESTART=true`
    т.к. invasive (kills чужие user-sessions).

    Note: pids аргумент игнорируется по содержанию — service restart kills
    ВСЕ rphost workers; ragent респавнит fresh ones с активным filter.
    На success returnem killed=list(pids) для unified API формы.
    """
    if sys.platform != "win32":
        return {"killed": [], "failed": [], "method": "noop"}
    cmd = (
        "Restart-Service -Name '1C:Enterprise 8.3 Server Agent' "
        "-Force -ErrorAction Stop; Write-Output 'OK'"
    )
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True,
            text=True,
            timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (subprocess.SubprocessError, OSError) as e:
        return {
            "killed": [],
            "failed": [{"pid": p, "error": str(e)} for p in pids],
            "method": "service.restart",
        }
    if result.returncode == 0 and "OK" in (result.stdout or ""):
        return {"killed": list(pids), "failed": [], "method": "service.restart"}
    err = (result.stderr or result.stdout or "").strip()
    return {
        "killed": [],
        "failed": [
            {"pid": p, "error": err or f"powershell exit={result.returncode}"} for p in pids
        ],
        "method": "service.restart",
    }


def _recycle_via_taskkill(pids: list) -> dict:
    """Fallback: hard taskkill /F. SYSTEM-owned rphost → Access Denied."""
    killed: list = []
    failed: list = []
    for pid in pids:
        try:
            result = subprocess.run(
                ["taskkill.exe", "/F", "/PID", str(pid)],
                capture_output=True,
                text=True,
                timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if result.returncode == 0:
                killed.append(pid)
            else:
                err = (result.stderr or result.stdout or "").strip()
                failed.append({"pid": pid, "error": err or f"taskkill exit={result.returncode}"})
        except (subprocess.SubprocessError, OSError) as e:
            failed.append({"pid": pid, "error": str(e)})
    return {"killed": killed, "failed": failed, "method": "taskkill"}


# ---------------------------------------------------------------------------
# §12 Level 1 — health-check probes (K8s-style readiness pattern)
# ---------------------------------------------------------------------------


def _hc_probe_dbgs_port(host: str = "localhost", port: int = 1550) -> dict:
    """TCP probe для dbgs.exe RDBG endpoint. Cheap (50ms timeout)."""
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.05)
    try:
        sock.connect((host, port))
        sock.close()
        return {"status": "pass", "detail": f"listening on {host}:{port}"}
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return {
            "status": "fail",
            "detail": f"{host}:{port} not reachable ({e})",
            "fix": "start ragent service with -debug -http flags",
        }


def _hc_probe_ragent_debug_flag() -> dict:
    """Verify ragent service has -debug + -http flags (Windows-only)."""
    if sys.platform != "win32":
        return {"status": "warn", "detail": "non-Windows — skip"}
    cmd = (
        "Get-CimInstance Win32_Service -Filter \"Name='1C:Enterprise 8.3 Server Agent'\" "
        "| Select-Object -ExpandProperty PathName"
    )
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (subprocess.SubprocessError, OSError) as e:
        return {"status": "fail", "detail": f"PowerShell exec failed: {e}"}
    if result.returncode != 0:
        return {"status": "fail", "detail": "service not found"}
    path = (result.stdout or "").strip()
    has_debug = "-debug" in path
    has_http = "-http" in path
    if has_debug and has_http:
        return {"status": "pass", "detail": "ragent has -debug -http"}
    missing = [f for f, present in (("-debug", has_debug), ("-http", has_http)) if not present]
    return {
        "status": "fail",
        "detail": f"ragent missing flags: {missing}",
        "fix": "scripts/enable-1c-server-debug-http.cmd (run as admin)",
    }


def _hc_probe_rphost_baseline() -> dict:
    """Count pre-existing rphost.exe processes."""
    rphosts = detect_pre_existing_rphosts()
    if not rphosts:
        return {"status": "pass", "detail": "no pre-existing rphost — fresh env"}
    pids = [r["pid"] for r in rphosts]
    return {
        "status": "warn",
        "detail": f"{len(pids)} pre-existing rphost(s): {pids}",
        "fix": "kill-stale-rphosts (auto-prepare action)",
    }


def _hc_probe_rac_available() -> dict:
    """rac.exe found + reachable cluster?"""
    rac = _find_rac_exe()
    if not rac:
        return {
            "status": "warn",
            "detail": "rac.exe not found in standard paths",
            "fix": "install 1С platform OR rely on taskkill fallback",
        }
    cluster = _rac_get_cluster_uuid(rac)
    if not cluster:
        return {
            "status": "warn",
            "detail": f"rac.exe found at {rac} but cluster unreachable",
            "fix": "check ragent on :1540",
        }
    return {"status": "pass", "detail": f"rac.exe + cluster {cluster[:8]}…"}


def _hc_probe_env_vars() -> dict:
    """Env vars для force_recycle paths."""
    import os

    rac_user = bool(os.environ.get("RAC_CLUSTER_USER", "").strip())
    rac_pwd = bool(os.environ.get("RAC_CLUSTER_PWD", ""))
    svc_restart = os.environ.get("BSL_DEBUG_ALLOW_SERVICE_RESTART", "").lower() == "true"
    flags = {
        "RAC_CLUSTER_USER": rac_user,
        "RAC_CLUSTER_PWD": rac_pwd,
        "BSL_DEBUG_ALLOW_SERVICE_RESTART": svc_restart,
    }
    return {"status": "pass", "detail": f"env: {flags}", "_extras": flags}


def _hc_probe_sddl_au_grant() -> dict:
    """SDDL contains AU ACE for Service Stop/Start (Fix #4 enabler)?"""
    if sys.platform != "win32":
        return {"status": "warn", "detail": "non-Windows — skip"}
    try:
        result = subprocess.run(
            ["sc.exe", "sdshow", "1C:Enterprise 8.3 Server Agent"],
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (subprocess.SubprocessError, OSError) as e:
        return {"status": "warn", "detail": f"sc sdshow failed: {e}"}
    if result.returncode != 0:
        return {"status": "warn", "detail": "sc sdshow returned non-zero"}
    sddl = (result.stdout or "").strip()
    has_au = "(A;;LCSWRPWPCR;;;AU)" in sddl
    if has_au:
        return {"status": "pass", "detail": "AU ACE present (Fix #4 path enabled)"}
    return {
        "status": "warn",
        "detail": "AU ACE not found — service.restart требует admin",
        "fix": "scripts/grant-1c-debug-permissions.ps1 (run as admin once)",
    }


def _hc_probe_active_session(client) -> dict:
    """wrapper-side state — есть ли активная debug session?"""
    if client is None or not getattr(client, "_attached", False):
        return {"status": "pass", "detail": "no active debug session"}
    return {
        "status": "pass",
        "detail": f"attached to {client.infobase_alias}, session={client.session_id[:8]}…",
    }


def _hc_probe_cluster_load() -> dict:
    """Roadmap §12.7 — warn если rphost'ы под большой нагрузкой.

    Threshold: env BSL_DEBUG_CONN_THRESHOLD (default 10). Высокая нагрузка
    указывает что debug может тормозить prod-traffic; user должен решить
    стоит ли force_recycle (kills active sessions) или подождать low-load
    окно.
    """
    import os

    rac = _find_rac_exe()
    if not rac:
        return {"status": "warn", "detail": "rac.exe not found — skip"}
    cluster = _rac_get_cluster_uuid(rac)
    if not cluster:
        return {"status": "warn", "detail": "cluster unreachable — skip"}
    threshold = int(os.environ.get("BSL_DEBUG_CONN_THRESHOLD", "10"))
    try:
        result = subprocess.run(
            [rac, "process", "list", f"--cluster={cluster}", *_rac_auth_args()],
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (subprocess.SubprocessError, OSError) as e:
        return {"status": "warn", "detail": f"rac process list failed: {e}"}
    if result.returncode != 0:
        return {"status": "warn", "detail": "rac process list non-zero"}
    high_load: list = []
    current_pid: Optional[int] = None
    for raw in result.stdout.splitlines():
        line = raw.strip()
        if line.startswith("pid"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                try:
                    current_pid = int(parts[1].strip())
                except ValueError:
                    current_pid = None
        elif line.startswith("connections") and current_pid is not None:
            parts = line.split(":", 1)
            if len(parts) == 2:
                try:
                    conns = int(parts[1].strip())
                    if conns > threshold:
                        high_load.append({"pid": current_pid, "connections": conns})
                except ValueError:
                    pass
    if high_load:
        return {
            "status": "warn",
            "detail": f"high-load rphost(s) >{threshold} conns: {high_load}",
            "fix": "wait for low-load window OR force_recycle (kills active sessions)",
        }
    return {"status": "pass", "detail": f"all rphost'ы ≤{threshold} connections"}


def _hc_recommend_workflow(checks: dict) -> str:
    """Pick workflow path based on probe results."""
    if checks.get("dbgs_port_1550", {}).get("status") == "fail":
        return "read-only"
    rphost_warn = checks.get("rphost_count_baseline", {}).get("status") == "warn"
    rac_ok = checks.get("rac_exe_path", {}).get("status") == "pass"
    svc_ok = (
        checks.get("env_vars", {}).get("_extras", {}).get("BSL_DEBUG_ALLOW_SERVICE_RESTART")
        and checks.get("sddl_au_grant", {}).get("status") == "pass"
    )
    if not rphost_warn:
        return "thin-client"  # no pre-existing → all paths work
    if rac_ok:
        return "force-recycle"  # Solution A (rac path)
    if svc_ok:
        return "service-restart"  # Solution A2 (Fix #4)
    return "thin-client"  # fallback: trigger ТОЛЬКО через UI


def _hc_collect_checks(client) -> dict:
    """Run all probes in cheap-first order. Returns checks dict."""
    return {
        "dbgs_port_1550": _hc_probe_dbgs_port(),
        "rac_exe_path": _hc_probe_rac_available(),
        "ragent_debug_flag": _hc_probe_ragent_debug_flag(),
        "rphost_count_baseline": _hc_probe_rphost_baseline(),
        "cluster_load": _hc_probe_cluster_load(),
        "env_vars": _hc_probe_env_vars(),
        "sddl_au_grant": _hc_probe_sddl_au_grant(),
        "active_session": _hc_probe_active_session(client),
        "infobase_list": _hc_probe_infobase_list(),
    }


def _hc_probe_infobase_list() -> dict:
    """Roadmap 260511 §3.3 partial — surface available infobases в health_check.

    Не полный bp_fire_smoke (тот требует triggering BSL — invasive в probe
    mode), но lists available infobases чтобы пользователь сразу видел
    valid aliases вместо silent invalid-alias path.
    """
    rac_exe = _find_rac_exe()
    if not rac_exe:
        return {"status": "skip", "detail": "rac.exe not found — cannot list infobases"}
    cluster = _rac_get_cluster_uuid(rac_exe)
    if not cluster:
        return {"status": "skip", "detail": "cluster unreachable"}
    infobases = _rac_list_infobases(rac_exe, cluster)
    if not infobases:
        return {"status": "warn", "detail": "cluster has zero infobases registered"}
    return {
        "status": "pass",
        "detail": f"{len(infobases)} infobase(s) discovered",
        "_extras": {"infobases": [ib["name"] for ib in infobases]},
    }


# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------
mcp = FastMCP("1c-debug")


@mcp.tool()
async def debug_connect(
    debug_url: str = "http://localhost:1550",
    infobase_alias: str = "TestDB",
    force_recycle_rphost: bool = False,
    recycle_strategy: str = "auto",
) -> str:
    """Connect to 1C debug agent and attach as debug client.

    IMPORTANT: Only ONE debug UI can be active per infobase.
    If EDT is debugging, you'll get 'ibInDebug' (read-only).
    Stop EDT debugging first for full access ('registered').

    Args:
        debug_url: URL of 1C debug agent (default: http://localhost:1550)
        infobase_alias: Infobase name in 1C cluster. Validated against
            `rac infobase summary list` perед attach — если не найден,
            возвращает status=error с available list (roadmap 260511 §3.1
            P0, closes RC1 из GKSTCPLK-2468). Validation graceful skip'ится
            если rac.exe/cluster unreachable.
        force_recycle_rphost: DEPRECATED — используй recycle_strategy.
            Backward-compat: True → recycle_strategy="pre_existing".
        recycle_strategy: roadmap 260511 §3.2 P0. Один из:
            "auto" (default) — = "pre_existing" если force_recycle_rphost=True,
                иначе "none"
            "none" — preflight-warning mode (текущее default поведение)
            "pre_existing" — kill только pre-existing pids (existing
                force_recycle_rphost=True behaviour)
            "all_rphosts_of_ib" — kill ВСЕ rphost workers обслуживающие
                эту IB через `rac process list --infobase` (closes RC2 —
                HTTP-service spawned rphost вне pre-existing snapshot).
                Требует valid infobase_alias.
            "all_rphosts_of_cluster" — kill ВСЕ rphost cluster'а (HIGH RISK:
                разрыв всех user sessions). Только для personal dev-баз.
    """
    global _client
    if _client and _client._attached:
        await _client.close()

    # Roadmap 260511 §3.1 (P0) — validate infobase_alias ПЕРЕД attach.
    # Closes RC1 (silent registered=true для несуществующего alias).
    alias_validation = _validate_infobase_alias(infobase_alias)
    if alias_validation["status"] == "invalid":
        return json.dumps(
            {
                "status": "error",
                "reason": "infobase_alias_not_found",
                "provided": infobase_alias,
                "available": alias_validation["available"],
                "hint": (
                    "Use one of available infobases. Provide the cluster IB "
                    "name from `rac infobase list`, not IIS publication name "
                    "or arbitrary alias. See roadmap 260511 §3.1."
                ),
            },
            ensure_ascii=False,
            indent=2,
        )

    # Resolve recycle_strategy (backward-compat для force_recycle_rphost).
    if recycle_strategy == "auto":
        recycle_strategy = "pre_existing" if force_recycle_rphost else "none"
    if recycle_strategy not in (
        "none",
        "pre_existing",
        "all_rphosts_of_ib",
        "all_rphosts_of_cluster",
    ):
        return json.dumps(
            {
                "status": "error",
                "reason": "invalid_recycle_strategy",
                "provided": recycle_strategy,
                "allowed": [
                    "auto",
                    "none",
                    "pre_existing",
                    "all_rphosts_of_ib",
                    "all_rphosts_of_cluster",
                ],
            },
            ensure_ascii=False,
            indent=2,
        )

    # Preflight (Solution B): snapshot rphost.exe ДО attach. Roadmap §11.
    pre_existing_rphosts = detect_pre_existing_rphosts()

    _client = RDBGClient(debug_url, infobase_alias)
    try:
        version = await _client.get_api_version()
        existing_id = await _client.get_debug_id()
        attach_result = await _client.attach()
        # Post-attach handshake (yukon39 Debugee.attach() lines 97-109,
        # canonical 4-step sequence): initSettings → clearBreakOnNextStatement →
        # setAutoAttachSettings. Required for eval/step/variables — without the
        # full sequence RDBG returns HTTP 400 «UI+ - часть отладки не зарегистрирована».
        if _client._registered:
            try:
                await _client.init_settings()
                await _client.clear_break_on_next_statement()
                await _client.set_auto_attach_settings()
            except Exception as e:
                log.warning("[connect] post-attach handshake failed: %s", e)

        # Solution A: force-recycle ПОСЛЕ setAutoAttachSettings — фильтр уже
        # pushed в dbgs, fresh rphost'ы прочитают его на регистрации.
        # Roadmap 260511 §3.2 (P0): extended recycle_strategy (closes RC2).
        recycle_info: Optional[dict] = None
        pids_to_kill: list[int] = []
        if recycle_strategy != "none" and _client._registered:
            # Resolve pid list based on strategy
            if recycle_strategy == "pre_existing":
                pids_to_kill = [r["pid"] for r in pre_existing_rphosts]
            elif recycle_strategy == "all_rphosts_of_ib":
                # Requires resolved infobase UUID from validation step
                if alias_validation["status"] != "valid":
                    return json.dumps(
                        {
                            "status": "error",
                            "reason": "recycle_strategy_requires_valid_alias",
                            "recycle_strategy": recycle_strategy,
                            "alias_validation": alias_validation,
                            "hint": (
                                "all_rphosts_of_ib needs cluster reachable + "
                                "alias validated. Use recycle_strategy="
                                "pre_existing for snapshot-based recycle."
                            ),
                        },
                        ensure_ascii=False,
                        indent=2,
                    )
                rac_exe = _find_rac_exe()
                cluster = _rac_get_cluster_uuid(rac_exe) if rac_exe else None
                if rac_exe and cluster:
                    pids_to_kill = _rac_list_rphosts_of_infobase(
                        rac_exe, cluster, alias_validation["uuid"]
                    )
            elif recycle_strategy == "all_rphosts_of_cluster":
                # HIGH RISK — kill every rphost in cluster
                pids_to_kill = [r["pid"] for r in detect_pre_existing_rphosts()]
                # Also include rphosts that may not be detected via process
                # snapshot (cluster-wide perspective via rac)
                rac_exe = _find_rac_exe()
                cluster = _rac_get_cluster_uuid(rac_exe) if rac_exe else None
                if rac_exe and cluster:
                    pid_to_uuid = _rac_list_processes_by_pid(rac_exe, cluster)
                    for pid in pid_to_uuid.keys():
                        if pid not in pids_to_kill:
                            pids_to_kill.append(pid)
        if pids_to_kill:
            # Fix #4 §12.8: env BSL_DEBUG_DRY_RUN_RECYCLE=true → preview only
            import os

            dry_run = os.environ.get("BSL_DEBUG_DRY_RUN_RECYCLE", "").lower() == "true"
            log.warning(
                "[connect] recycle_strategy=%s killing rphost(s): %s%s",
                recycle_strategy,
                pids_to_kill,
                " (DRY-RUN)" if dry_run else "",
            )
            # §12.3 Level 3 — track recycle invocation
            _client._force_recycle_invoked = True
            kill_result = force_recycle_rphost_processes(pids_to_kill, dry_run=dry_run)
            _client._recycle_method_used = kill_result.get("method")
            # Дать ragent ~3с на spawn fresh rphost + ping_loop'у поймать event
            # (DBGUIExtCmdInfoStarted → handler → attachDebugTarget).
            await asyncio.sleep(3.0)
            recycle_info = {
                "_tag": "force_recycle_result",
                "strategy": recycle_strategy,
                "requested_pids": pids_to_kill,
                "killed": kill_result["killed"],
                "failed": kill_result["failed"],
                "wait_after_kill_sec": 3.0,
            }

        targets = await _client.get_targets()
        stopped = _find_stopped_target(targets)

        # Auto-attach to ALL targets (not just stopped) — RDBG delivers BP stops
        # only to attached targets. Без этого BPs ставятся, но никогда не fire.
        if _client._registered and targets:
            all_target_ids = [t.get("id") for t in targets if t.get("id")]
            if all_target_ids:
                await _client.attach_debug_targets(all_target_ids)

        result = {
            "status": "connected",
            "api_version": version,
            "attach": attach_result,
            "infobase": infobase_alias,
            "existing_debug_ui": existing_id,
            "targets": targets,
            "stopped_target": stopped,
        }

        # Surface alias validation status в result (roadmap 260511 §3.1).
        result["alias_validation"] = alias_validation

        # Solution B: preflight warning when есть pre-existing rphost'ы и
        # пользователь НЕ запросил force-recycle — surface gap явно вместо
        # silent BP-no-fire (root cause § 10).
        if pre_existing_rphosts and recycle_strategy == "none":
            result["pre_existing_rphost_warning"] = {
                "_tag": "preflight_warning",
                "message": (
                    "Detected rphost.exe process(es) alive ДО debug_connect. "
                    "RDBG protocol cannot retroactively attach them "
                    "(DBGUIExtCmdInfoStarted event fires только на spawn, не "
                    "replay'ится при регистрации новой debug session). BPs на "
                    "BSL, исполняемом этими rphost'ами (например IIS HTTP-services, "
                    "background jobs, web-client'ы), не будут fire."
                ),
                "pre_existing_pids": [r["pid"] for r in pre_existing_rphosts],
                "next_steps": [
                    "Solution C: триггер через UI запущенный ПОСЛЕ debug_connect "
                    "(тонкий клиент с /Debug -http /DebuggerURL=http://localhost:1550)",
                    "Solution A (snapshot): retry с recycle_strategy=pre_existing "
                    "(kills pre-existing snapshot pids; ragent spawn'ит fresh "
                    "worker с активным filter; РИСК: разрыв user sessions в "
                    "killed rphost'ах)",
                    "Solution A+ (extended, roadmap 260511 §3.2): retry с "
                    "recycle_strategy=all_rphosts_of_ib (covers HTTP-service "
                    "spawned rphost вне pre-existing snapshot — closes RC2)",
                    "Manual: Console кластера → «Выключить» процесс (graceful "
                    "drain активных сессий другому worker'у) → retry connect",
                ],
                "roadmap_ref": (
                    "docs/roadmap/260508_ROADMAP_BSL_DEBUG_WRAPPER_POST_BP_HANDSHAKE.md §10 + §11"
                ),
            }
        if recycle_info is not None:
            result["force_recycle"] = recycle_info

        if not _client._registered:
            result["warning"] = (
                "Got 'ibInDebug' — another debugger (EDT?) is active. "
                "Stop EDT debugging for full access."
            )
        return json.dumps(result, ensure_ascii=False, indent=2)
    except Exception as e:
        log.exception("Connect failed")
        return json.dumps({"status": "error", "error": str(e)}, ensure_ascii=False)


@mcp.tool()
async def debug_disconnect() -> str:
    """Disconnect from 1C debug agent."""
    client = _get_client()
    result = await client.detach()
    return json.dumps({"status": "disconnected", "result": result})


_SESSION_STORE_DIR = "data/debug_sessions"

# §13.x HMR-restart recovery: persisted active session state path.
# When the MCP subprocess is hot-reloaded by mcp_hmr_proc.py, all in-memory
# state is lost — including session_id и UI+ handshake. RDBG, however, still
# has our session registered server-side (60s GC grace). Persisting session_id
# to disk lets the new subprocess reuse it on cold start, so RDBG recognizes
# the same dbgui and the first call doesn't return 400 «UI+ не зарегистрирована».
_ACTIVE_SESSION_PATH = "data/debug_sessions/.active.json"

# §12.9 Stale-detection: timestamp когда модуль был импортирован Python'ом.
# При каждом MCP-вызове сравниваем mtime файла с _MODULE_LOADED_AT —
# если файл новее, MCP-процесс крутит устаревший код, нужен /mcp reconnect.
import time as _time

_MODULE_LOADED_AT = _time.time()


def _get_stale_hint() -> Optional[str]:
    """Return user-facing hint если wrapper file изменён ПОСЛЕ старта процесса.

    Returns None если файл свежий (нет stale) ИЛИ если mtime check failed.
    Ненавязчивая подсказка — не блокирует, не raise.
    """
    import os

    try:
        mtime = os.path.getmtime(__file__)
    except OSError:
        return None
    if mtime <= _MODULE_LOADED_AT:
        return None
    age_sec = int(mtime - _MODULE_LOADED_AT)
    return (
        f"Wrapper file modified {age_sec}s after MCP start — "
        f"running stale code. Run /mcp reconnect to pick up changes."
    )


def _persist_session_summary(summary: dict) -> Optional[str]:
    """Mirror session summary to data/debug_sessions/<id>.json для cross-session diff."""
    import os

    try:
        os.makedirs(_SESSION_STORE_DIR, exist_ok=True)
        path = os.path.join(_SESSION_STORE_DIR, f"{summary['session_id']}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(summary, f, ensure_ascii=False, indent=2)
        return path
    except (OSError, KeyError):
        return None


# ---------------------------------------------------------------------------
# §13.x HMR-restart recovery: active session persistence
# ---------------------------------------------------------------------------
# Goal: survive `mcp_hmr_proc.py` subprocess restart (triggered by source-file
# change) without losing UI+ registration with RDBG. State written atomically
# (tmp + os.replace) после каждого successful attach() — so even after the
# UI+ escalation path regenerates session_id, the new id replaces the old one
# on disk. detach() очищает файл — graceful disconnect ≠ HMR restart.


def _persist_active_session(client: "RDBGClient") -> None:
    """Write active session state to _ACTIVE_SESSION_PATH (atomic via os.replace).

    Called from RDBGClient.attach() right after _registered=True — including
    the post-escalation path in _ui_plus_full_reattach_and_retry. Silent on
    OSError: persistence is best-effort, missing file just falls back to
    «cold» reconnect (which still works, just costs one extra round-trip).
    """
    if not (client._attached and client._registered):
        return
    import os

    state = {
        "session_id": client.session_id,
        "debug_url": client.debug_url,
        "infobase_alias": client.infobase_alias,
        "persisted_at": _time.time(),
        # B2 roadmap 260708 §7.5: per-module line offsets survive HMR restart.
        "line_offsets": getattr(client, "_line_offsets", {}) or {},
    }
    try:
        os.makedirs(os.path.dirname(_ACTIVE_SESSION_PATH) or ".", exist_ok=True)
        tmp = _ACTIVE_SESSION_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False)
        os.replace(tmp, _ACTIVE_SESSION_PATH)
    except OSError:
        log.debug("[active-session] persist failed", exc_info=True)


def _load_active_session() -> Optional[dict]:
    """Read persisted state. Returns None if absent or unreadable.

    No TTL check: stale state file just causes one 400 → escalation re-attach
    path covers it (existing UI+ recovery in _post). Cleaner than guessing
    a TTL value that doesn't match RDBG's actual GC behavior.
    """
    try:
        with open(_ACTIVE_SESSION_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def _clear_active_session() -> None:
    """Remove persisted state (graceful detach / disconnect)."""
    import os

    try:
        os.remove(_ACTIVE_SESSION_PATH)
    except OSError:
        pass


def _load_session_summary(session_id: str) -> Optional[dict]:
    """Load persisted session summary by ID."""
    import os

    path = os.path.join(_SESSION_STORE_DIR, f"{session_id}.json")
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _diff_summaries(prev: dict, curr: dict) -> dict:
    """Compute regression-relevant diff between 2 session summaries."""
    p_bp = prev.get("breakpoints", {})
    c_bp = curr.get("breakpoints", {})
    p_ev = prev.get("evaluations", {})
    c_ev = curr.get("evaluations", {})
    diff = {
        "prev_session": prev.get("session_id"),
        "curr_session": curr.get("session_id"),
        "regression_indicators": [],
        "deltas": {
            "bp_set_count": c_bp.get("set_count", 0) - p_bp.get("set_count", 0),
            "bp_fire_count": c_bp.get("fire_count", 0) - p_bp.get("fire_count", 0),
            "eval_count": c_ev.get("count", 0) - p_ev.get("count", 0),
            "eval_failures": c_ev.get("failures", 0) - p_ev.get("failures", 0),
            "ui_plus_retries": (curr.get("ui_plus_retries", 0) - prev.get("ui_plus_retries", 0)),
            "stop_events_count": (
                len(curr.get("stop_events", [])) - len(prev.get("stop_events", []))
            ),
        },
    }
    if diff["deltas"]["bp_fire_count"] < 0:
        diff["regression_indicators"].append(
            f"BP fire_count regressed: -{abs(diff['deltas']['bp_fire_count'])}"
        )
    if diff["deltas"]["eval_failures"] > 0:
        diff["regression_indicators"].append(
            f"eval failures increased: +{diff['deltas']['eval_failures']}"
        )
    if diff["deltas"]["ui_plus_retries"] > 0:
        diff["regression_indicators"].append(
            f"UI+ retries increased: +{diff['deltas']['ui_plus_retries']}"
        )
    diff["verdict"] = "REGRESSION" if diff["regression_indicators"] else "NO_REGRESSION"
    return diff


@mcp.tool()
async def debug_session_diff(prev_session_id: str, curr_session_id: Optional[str] = None) -> str:
    """Roadmap §12.7 Level 3 extension — cross-session diff для regression detection.

    Compares 2 session summaries. Returns deltas + regression_indicators list.

    Args:
        prev_session_id: baseline session UUID
        curr_session_id: comparison session UUID (default: current active session)
    """
    prev = _load_session_summary(prev_session_id)
    if not prev:
        return json.dumps(
            {"status": "error", "error": f"prev_session_id {prev_session_id} not found"}
        )
    if curr_session_id:
        curr = _load_session_summary(curr_session_id)
        if not curr:
            return json.dumps(
                {"status": "error", "error": f"curr_session_id {curr_session_id} not found"}
            )
    else:
        # Build summary from current _client
        global _client
        if _client is None:
            return json.dumps(
                {"status": "error", "error": "no current session and no curr_session_id"}
            )
        curr_raw = await debug_session_summary(format="json")
        curr = json.loads(curr_raw)
    diff = _diff_summaries(prev, curr)
    # Fix D §12.9: passive stale hint в response
    stale = _get_stale_hint()
    if stale:
        diff["_stale_hint"] = stale
    return json.dumps(diff, ensure_ascii=False, indent=2)


@mcp.tool()
async def debug_session_summary(format: str = "json") -> str:
    """Roadmap §12.3 Level 3 — post-mortem session metrics.

    Returns aggregated metrics (BPs set/fired by location, eval count + UI+ retries,
    recycle method used, stop event timeline) для текущей RDBGClient session.
    Tracking is in-process counters (append-only); no DB persistence.

    Args:
        format: "json" (structured) | "markdown" (human-readable PR transcript) |
                "artifacts" (P1.B roadmap 260511: ZIP bundle с summary.json +
                summary.md + breakpoints_cache.json + stop_events.json +
                logpoint_log.jsonl (если есть) + stack_snapshots/<tid>.json).
                Returns `{path, size_bytes, files[]}`. ZIP в `data/debug_artifacts/<session>.zip`

    Если нет активной session (debug_connect не вызывался) — возвращает
    {"status": "no_session"}.
    """
    global _client
    if _client is None:
        return json.dumps({"status": "no_session"})

    cache_lines_total = sum(len(e.get("lines", [])) for e in _client._set_breakpoints_cache)
    summary = {
        "session_id": _client.session_id,
        "started_at": _client._session_started_at,
        "infobase_alias": _client.infobase_alias,
        "attached": _client._attached,
        "breakpoints": {
            "set_count": cache_lines_total,
            "fire_count": _client._bp_fire_count,
            "by_location": dict(_client._bp_by_location),
            "fire_rate": (
                _client._bp_fire_count / cache_lines_total if cache_lines_total else None
            ),
        },
        "evaluations": {
            "count": _client._eval_count,
            "failures": _client._eval_failures,
            "errors": list(_client._eval_errors[-10:]),  # last 10
        },
        "ui_plus_retries": _client._ui_plus_retry_count,
        "recycle": {
            "force_invoked": _client._force_recycle_invoked,
            "method_used": _client._recycle_method_used,
        },
        "stop_events": list(_client._stop_events),
        "rphosts_seen": list(_client._rphosts_seen),
    }
    # Persist для cross-session diff (§12.7)
    _persist_session_summary(summary)
    # Fix D §12.9: passive stale hint в response
    stale = _get_stale_hint()
    if stale:
        summary["_stale_hint"] = stale
    if format == "markdown":
        return _render_summary_md(summary)
    if format == "artifacts":
        result = artifacts.build_session_zip(_client, summary, _render_summary_md)
        return json.dumps(result, ensure_ascii=False, indent=2)
    return json.dumps(summary, ensure_ascii=False, indent=2)


def _render_summary_md(summary: dict) -> str:
    """P1.B: extracted markdown render for reuse via artifacts ZIP bundle."""
    bp = summary["breakpoints"]
    ev = summary["evaluations"]
    rec = summary["recycle"]
    md_lines = [
        f"## Debug Session {summary['session_id'][:8]} ({summary['started_at']})",
        f"- Infobase: **{summary['infobase_alias']}**",
        f"- BPs: **{bp['set_count']} set, {bp['fire_count']} fired** "
        f"({(bp['fire_rate'] or 0) * 100:.0f}% fire rate)",
        f"- Locations: {bp['by_location'] or '—'}",
        f"- Evals: **{ev['count']}** (failures: {ev['failures']})",
        f"- UI+ retries: **{summary['ui_plus_retries']}**",
        f"- Recycle: invoked={rec['force_invoked']}, method={rec['method_used'] or '—'}",
        f"- Stop events: **{len(summary['stop_events'])}**",
        f"- Targets seen: {len(summary['rphosts_seen'])}",
    ]
    return "\n".join(md_lines)


@mcp.tool()
async def debug_health_check(mode: str = "probe", actions: Optional[list] = None) -> str:
    """Roadmap §12.1 Level 1 — preflight environment readiness check.

    JSON shape (K8s readiness pattern):
        {
          "ready": bool,
          "version": str,
          "mode": "probe"|"prepare",
          "checks": {<probe_id>: {status, detail, fix?}},
          "auto_prepare_available": [str],
          "recommended_workflow": "thin-client|force-recycle|service-restart|read-only",
          "elapsed_ms": int,
          "actions_executed": [{action, result}]  # only когда mode=prepare
        }

    Args:
        mode: "probe" (default, read-only) — collect probes, return status.
              "prepare" — выполнить actions из whitelist для auto-fix.
        actions: list of action tokens (только для mode=prepare). Whitelist:
                 ["kill-stale-rphosts", "restart-ragent"]. NEVER auto-modify
                 SDDL or env vars (security boundary, surface как manual fix).
    """
    import time

    t0 = time.time()
    global _client
    checks = _hc_collect_checks(_client)
    fails = [k for k, v in checks.items() if v.get("status") == "fail"]
    warns = [k for k, v in checks.items() if v.get("status") == "warn"]
    ready = len(fails) == 0
    auto_prepare = []
    if "rphost_count_baseline" in warns:
        auto_prepare.append("kill-stale-rphosts")
    sddl_pass = checks.get("sddl_au_grant", {}).get("status") == "pass"
    svc_env = checks.get("env_vars", {}).get("_extras", {}).get("BSL_DEBUG_ALLOW_SERVICE_RESTART")
    if sddl_pass and svc_env:
        auto_prepare.append("restart-ragent")

    actions_executed: list = []
    if mode == "prepare":
        if not actions:
            return json.dumps(
                {"status": "error", "error": "mode=prepare requires non-empty actions list"}
            )
        whitelist = {"kill-stale-rphosts", "restart-ragent"}
        for action in actions:
            if action not in whitelist:
                actions_executed.append({"action": action, "result": "rejected: not in whitelist"})
                continue
            if action == "kill-stale-rphosts":
                rphosts = detect_pre_existing_rphosts()
                pids = [r["pid"] for r in rphosts]
                if pids:
                    res = force_recycle_rphost_processes(pids)
                    actions_executed.append({"action": action, "result": res})
                else:
                    actions_executed.append({"action": action, "result": "no rphosts to kill"})
            elif action == "restart-ragent":
                res = _recycle_via_service([])
                actions_executed.append({"action": action, "result": res})
        # Re-probe after actions
        checks = _hc_collect_checks(_client)
        ready = all(v.get("status") != "fail" for v in checks.values())

    out = {
        "ready": ready,
        "version": "mcp_debug_server@2026-05-10",
        "mode": mode,
        "checks": checks,
        "auto_prepare_available": auto_prepare,
        "recommended_workflow": _hc_recommend_workflow(checks),
        "elapsed_ms": int((time.time() - t0) * 1000),
    }
    if mode == "prepare":
        out["actions_executed"] = actions_executed
    # Fix A §12.9: stale-detection — explicit warning в health_check response
    stale = _get_stale_hint()
    if stale:
        out["stale_warning"] = stale
    return json.dumps(out, ensure_ascii=False, indent=2)


@mcp.tool()
async def debug_targets() -> str:
    """List all debug targets (active sessions).

    Shows UUID, user name, target type (Server/ManagedClient), state.
    State 'StopOnNextLine' means stopped at breakpoint.
    """
    client = _get_client()
    targets = await client.get_targets()
    stopped = _find_stopped_target(targets)
    return json.dumps(
        {
            "targets": targets,
            "count": len(targets),
            "stopped_target": stopped,
        },
        ensure_ascii=False,
        indent=2,
    )


@mcp.tool()
async def debug_ping() -> str:
    """Ping debug server for pending events (breakpoint hit, target started/quit).

    Roadmap 260511 §3.6 (P2): после 3+ consecutive empty pings — append
    no_fire_diagnostics с auto-detected root-cause hints (RC1/RC2 from
    GKSTCPLK-2468 incident).
    """
    client = _get_client()
    events = await client.ping()
    # Track consecutive empty pings on client (P2 no-fire diagnostics)
    if not hasattr(client, "_consecutive_empty_pings"):
        client._consecutive_empty_pings = 0
    if events:
        client._consecutive_empty_pings = 0
    else:
        client._consecutive_empty_pings += 1
    result = {"events": events, "count": len(events)}
    if client._consecutive_empty_pings >= 3:
        result["no_fire_diagnostics"] = _build_no_fire_diagnostics(client)
    return json.dumps(result, ensure_ascii=False, indent=2)


def _build_no_fire_diagnostics(client) -> dict:
    """Auto-detect likely no-fire causes (roadmap 260511 §3.6 P2).

    Surfaces:
    - alias validity (if rac reachable)
    - targets_attached count
    - active rphosts in cluster
    - actionable suggestions
    """
    diag: dict = {
        "consecutive_empty_pings": client._consecutive_empty_pings,
        "infobase_alias": getattr(client, "infobase_alias", None),
        "session_id": getattr(client, "session_id", None),
    }
    # Targets check
    try:
        attached_ids = list(getattr(client, "_attached_targets", set()))
        diag["targets_attached"] = len(attached_ids)
    except Exception:
        diag["targets_attached"] = "unknown"
    # Alias validation
    alias = getattr(client, "infobase_alias", None) or ""
    if alias:
        validation = _validate_infobase_alias(alias)
        diag["infobase_validation"] = validation
    # Active rphosts
    try:
        rphosts = detect_pre_existing_rphosts()
        diag["active_rphost_pids"] = [r["pid"] for r in rphosts]
    except Exception:
        diag["active_rphost_pids"] = []
    # Build suggestions
    suggestions: list[str] = []
    if diag.get("infobase_validation", {}).get("status") == "invalid":
        suggestions.append(
            f"RC1: infobase_alias '{alias}' NOT in cluster. "
            f"Available: {diag['infobase_validation'].get('available', [])}. "
            "Reconnect with valid alias."
        )
    if diag.get("targets_attached") == 0 and diag.get("active_rphost_pids"):
        suggestions.append(
            "RC2: rphost'ы запущены но НЕ attached к debug session. "
            "Try: reconnect с recycle_strategy='all_rphosts_of_ib' или "
            "debug_launch_thin_client после connect (Solution C)."
        )
    if not diag.get("active_rphost_pids"):
        suggestions.append(
            "No rphosts running — trigger BSL via execute_code or "
            "debug_launch_thin_client to spawn one."
        )
    if not suggestions:
        suggestions.append(
            "BPs may be on inactive code paths. Try debug_break_on_next "
            "to catch ANY BSL operation, or set BP closer to trigger entry."
        )
    diag["suggestions"] = suggestions
    return diag


@mcp.tool()
async def debug_stack_trace(target_id: str = "") -> str:
    """Get call stack of a stopped debug target.

    Args:
        target_id: UUID from debug_targets. If empty, использует cached
            last_stopped_target_id (роадмап §13 P1.3, как `debug_variables`/
            `debug_evaluate`) или fallback на get_targets pull.

    Errors are surfaced as JSON `{"error": "..."}` instead of bubbling up
    as opaque MCP exceptions (pre-fix 2026-05-10: silent fail with empty
    body when get_call_stack или json.dumps raised — see live test).
    """
    try:
        client = _get_client()
        if not (client._attached and client._registered):
            return _error_json("Not connected. Call debug_connect first.", "not_connected")
        target_id, scanned = await _resolve_stopped_target(client, target_id)
        if not target_id:
            return _error_json("No stopped targets", "no_stopped_target", targets=scanned)
        stack = await client.get_call_stack(target_id)
        # P0.C roadmap 260511: enrich each frame with resolved_source (FQN + file path)
        enriched = _enrich_stack(stack)
        return json.dumps(
            {"target_id": target_id, "stack": enriched, "depth": len(enriched)},
            ensure_ascii=False,
            indent=2,
        )
    except Exception as e:
        log.exception("debug_stack_trace failed")
        return _error_json(_rdbg_error_text(e), type(e).__name__, target_id=target_id)


@mcp.tool()
async def debug_variables(
    target_id: str = "", stack_level: int = 0, expressions: Optional[list[str]] = None
) -> str:
    """Read local variables at current breakpoint.

    Two modes:
    - **Auto-discovery (default)**: parse BSL source at current line via
      uuid_index + bsl_locals to extract param names + Перем + assignments
      up to the line, then batch-eval them. Requires source in EDT export
      (default `<infobase>/Конфигурация/src/`). Returns `[{name, evalResult-
      State, resultValueInfo}, ...]`.
    - **Explicit names**: pass `expressions=["A", "B", ...]` to evaluate just
      those names (skips source parsing — works without source access).

    Args:
        target_id: UUID from debug_targets. If empty, uses cached
            _last_stopped_target_id (roadmap §13 P1.3) or get_targets pull.
        stack_level: 0 = current frame, 1 = caller, etc.
        expressions: explicit variable names to read. Default None → auto-
            discover from BSL source.
    """
    try:
        client = _get_client()
        if not (client._attached and client._registered):
            return _error_json("Not connected. Call debug_connect first.", "not_connected")
        target_id, _ = await _resolve_stopped_target(client, target_id)
        if not target_id:
            return _error_json("No stopped targets", "no_stopped_target", target_id=target_id)
        if expressions:
            variables = await client.eval_local_variables(
                target_uuid=target_id,
                stack_level=stack_level,
                expressions=expressions,
            )
            mode = "explicit"
        else:
            variables = await client.eval_locals_auto(
                target_uuid=target_id,
                stack_level=stack_level,
            )
            mode = "auto"
        return json.dumps(
            {
                "target_id": target_id,
                "variables": variables,
                "count": len(variables),
                "stack_level": stack_level,
                "mode": mode,
            },
            ensure_ascii=False,
            indent=2,
        )
    except Exception as e:
        # Graceful envelope (единый формат с debug_stack_trace/_error_json) вместо
        # opaque MCP-exception. Типичный кейс: RDBG 400 «вычисления только в
        # остановленном предмете отладки» когда target не на halt'е.
        log.exception("debug_variables failed")
        return _error_json(
            _rdbg_error_text(e), type(e).__name__, target_id=target_id, stack_level=stack_level
        )


@mcp.tool()
async def debug_evaluate(expression: str, target_id: str = "", stack_level: int = 0) -> str:
    """Evaluate a BSL expression in context of a stopped target.

    Args:
        expression: BSL expression (e.g. "Контрагент.ИНН", "ТекущаяДата()")
        target_id: UUID from debug_targets. If empty, использует ping
            cached state (P1.3) или fallback на get_targets pull.
        stack_level: 0 = current frame.
    """
    try:
        client = _get_client()
        if not (client._attached and client._registered):
            return _error_json("Not connected. Call debug_connect first.", "not_connected")
        target_id, _ = await _resolve_stopped_target(client, target_id)
        if not target_id:
            return _error_json("No stopped targets", "no_stopped_target", target_id=target_id)
        result = await client.eval_expression(
            expression=expression,
            target_uuid=target_id,
            stack_level=stack_level,
        )
        return json.dumps(
            {"expression": expression, "result": result}, ensure_ascii=False, indent=2
        )
    except Exception as e:
        # Graceful envelope (единый формат с debug_stack_trace/_error_json) вместо
        # opaque MCP-exception — типичный кейс RDBG 400 «вычисления только в
        # остановленном предмете отладки» при target не на halt'е.
        log.exception("debug_evaluate failed")
        return _error_json(
            _rdbg_error_text(e), type(e).__name__, expression=expression, target_id=target_id
        )


@mcp.tool()
async def debug_inspect_frame(
    target_id: str = "", stack_level: int = 0, context_radius: int = 3
) -> str:
    """A0 (roadmap 260708 §7.2): rich frame bundle в один вызов.

    Сворачивает цепочку debug_stack_trace → debug_variables → N×debug_evaluate
    в один ответ: текущий фрейм + resolved_source (FQN/файл) + auto-discovered
    локали + исходник строки ±context_radius (маркер `current` на текущей).
    Основной агент-центричный примитив (ADI/InspectCoder frame-bundle).

    Args:
        target_id: UUID; пусто → cached last_stopped → get_targets scan.
        stack_level: 0 = текущий/innermost фрейм, 1 = вызывающий, ...
        context_radius: строк исходника выше/ниже текущей (default 3).
    """
    try:
        client = _get_client()
        if not (client._attached and client._registered):
            return _error_json("Not connected. Call debug_connect first.", "not_connected")
        target_id, scanned = await _resolve_stopped_target(client, target_id)
        if not target_id:
            return _error_json("No stopped targets", "no_stopped_target", targets=scanned)
        bundle = await autonomy.build_frame_bundle(
            client,
            target_id,
            stack_level=stack_level,
            context_radius=context_radius,
        )
        return json.dumps(bundle, ensure_ascii=False, indent=2)
    except Exception as e:
        log.exception("debug_inspect_frame failed")
        return _error_json(_rdbg_error_text(e), type(e).__name__, target_id=target_id)


@mcp.tool()
async def debug_autotrace(
    object_id: str = "",
    line: int = 0,
    module_type: str = "CommonModule",
    property_id: str = "",
    phase: str = "collect",
    expect: Optional[dict] = None,
    timeout_sec: float = 20.0,
    stack_level: int = 0,
    context_radius: int = 3,
) -> str:
    """A1 (roadmap 260708 §7.3): автономный trace — BP → ждать fire → inspect →
    verdict → release, в минимуме ручной оркестрации.

    **Two-phase** (Ф-1 §7.0: trigger исполняется ВЫЗЫВАЮЩИМ через другой
    MCP-сервер `1c-mcp-crud`, поэтому wrapper не триггерит код сам):

    1. `phase="arm"` (нужны `object_id` + `line`): ставит BP (с авто-offset B2)
       + silent break-on-next → `{status:"armed", bp}`. Затем ВЫ триггерите код
       (execute_code / UI / JOB).
    2. `phase="collect"` (default): ждёт остановки до `timeout_sec`, собирает
       frame-bundle (A0), сверяет `expect`, делает Continue (release rphost).

    `expect`: `{"<BSL-выражение>": "<ожидаемое представление значения>", ...}` —
    verdict сравнивает строковое представление (как `debug_evaluate`, stack_level).

    **Контракт возврата (решение §5.2):** `{verdict, raw}`. `raw` — ВСЕГДА
    источник истины (`hit`, frame-bundle, stack). `verdict` — машинное суждение
    по `expect` (PASS/FAIL/NO_HIT/INCONCLUSIVE) или `null`, если `expect` не дан.
    ⚠ Ф-2: порядок фреймов (stack[0] vs stack[-1]) для многофреймовых стеков —
    смотри `raw.stack`; verdict/locals используют stack_level (как debug_evaluate).
    """
    try:
        client = _get_client()
        if not (client._attached and client._registered):
            return _error_json("Not connected. Call debug_connect first.", "not_connected")

        if phase == "arm":
            if not object_id or line <= 0:
                return _error_json(
                    "arm requires object_id and line>0",
                    "bad_args",
                    object_id=object_id,
                    line=line,
                )
            xml_mt, pid = _resolve_property_id(module_type, property_id)
            adj_line, applied_offset = _apply_line_offset(client, object_id, line)
            await client.set_breakpoints(
                module_type=xml_mt,
                object_id=object_id,
                property_id=pid,
                lines=[adj_line],
            )
            await client.set_break_on_next_statement(silent=True)
            return json.dumps(
                {
                    "status": "armed",
                    "bp": {
                        "object_id": object_id,
                        "line": adj_line,
                        "applied_offset": applied_offset,
                        "module_type": module_type,
                    },
                    "next": (
                        "trigger the code (execute_code / UI / JOB), then call "
                        "debug_autotrace(phase='collect', expect=...)"
                    ),
                },
                ensure_ascii=False,
                indent=2,
            )

        if phase != "collect":
            return _error_json(f"unknown phase '{phase}'", "bad_phase")

        # collect: poll for a stop (background ping_loop populates last_stopped).
        poll = 0.3
        waited = 0.0
        target_id = ""
        while waited < timeout_sec:
            target_id, _ = await _resolve_stopped_target(client, "")
            if target_id:
                break
            await asyncio.sleep(poll)
            waited += poll
        if not target_id:
            verdict = (
                {"status": "NO_HIT", "reason": f"no stop within {timeout_sec}s", "checked": []}
                if expect
                else None
            )
            return json.dumps(
                {"verdict": verdict, "raw": {"hit": False, "waited_sec": round(waited, 1)}},
                ensure_ascii=False,
                indent=2,
            )
        try:
            bundle = await autonomy.build_frame_bundle(
                client,
                target_id,
                stack_level=stack_level,
                context_radius=context_radius,
            )
            verdict = None
            if expect:
                verdict = await autonomy.evaluate_expect(
                    client,
                    target_id,
                    expect,
                    stack_level=stack_level,
                )
            return json.dumps(
                {"verdict": verdict, "raw": {"hit": True, **bundle}},
                ensure_ascii=False,
                indent=2,
            )
        finally:
            # Release rphost even on FAIL/exception (Шаблон 5 шаг 8).
            try:
                await client.step("Continue", target_uuid=target_id)
            except Exception:
                log.warning("autotrace collect: Continue failed", exc_info=True)
    except Exception as e:
        log.exception("debug_autotrace failed")
        return _error_json(_rdbg_error_text(e), type(e).__name__, phase=phase)


@mcp.tool()
async def debug_collection_info(expression: str, target_id: str = "", stack_level: int = 0) -> str:
    """C0 (roadmap 260708 §7.4): тип + размер коллекции для paging.

    Eval `ТипЗнч(<expression>)` + `<expression>.Количество()` в остановленном
    фрейме. Первый шаг перед debug_collection_page для больших
    ТаблицаЗначений / Массив / РезультатЗапроса.
    """
    try:
        client = _get_client()
        if not (client._attached and client._registered):
            return _error_json("Not connected. Call debug_connect first.", "not_connected")
        target_id, scanned = await _resolve_stopped_target(client, target_id)
        if not target_id:
            return _error_json("No stopped targets", "no_stopped_target", targets=scanned)
        type_res = await client.eval_expression(
            expression=f"ТипЗнч({expression})",
            target_uuid=target_id,
            stack_level=stack_level,
        )
        count_res = await client.eval_expression(
            expression=f"{expression}.Количество()",
            target_uuid=target_id,
            stack_level=stack_level,
        )
        return json.dumps(
            {
                "expression": expression,
                "type": autonomy._extract_eval_value(type_res),
                "count": autonomy._extract_eval_value(count_res),
            },
            ensure_ascii=False,
            indent=2,
        )
    except Exception as e:
        log.exception("debug_collection_info failed")
        return _error_json(_rdbg_error_text(e), type(e).__name__, expression=expression)


@mcp.tool()
async def debug_collection_page(
    expression: str,
    start: int = 0,
    count: int = 20,
    columns: Optional[list] = None,
    target_id: str = "",
    stack_level: int = 0,
) -> str:
    """C0 (roadmap 260708 §7.4): страница индексируемой коллекции.

    Ленивый доступ к большим `ТаблицаЗначений` / `Массив` / выгрузке
    `РезультатЗапроса` без обрезки или взрыва контекста: batch `<expression>[i]`
    (+ `.<column>` на строку при `columns`) одним evalLocalVariables POST.

    Args:
        expression: BSL-выражение коллекции (напр. `ТаблицаДанных`).
        start: индекс первого элемента (0-based).
        count: размер страницы (cap 200).
        columns: колонки ТаблицаЗначений для чтения по строке (None = элемент целиком).
        target_id / stack_level: как в debug_evaluate.
    """
    try:
        client = _get_client()
        if not (client._attached and client._registered):
            return _error_json("Not connected. Call debug_connect first.", "not_connected")
        target_id, scanned = await _resolve_stopped_target(client, target_id)
        if not target_id:
            return _error_json("No stopped targets", "no_stopped_target", targets=scanned)
        count = max(1, min(int(count), 200))
        exprs = autonomy.build_page_expressions(expression, int(start), count, columns)
        values = await client.eval_local_variables(
            target_uuid=target_id,
            stack_level=stack_level,
            expressions=exprs,
        )
        return json.dumps(
            {
                "expression": expression,
                "start": int(start),
                "count": count,
                "columns": columns or None,
                "values": values,
            },
            ensure_ascii=False,
            indent=2,
        )
    except Exception as e:
        log.exception("debug_collection_page failed")
        return _error_json(_rdbg_error_text(e), type(e).__name__, expression=expression)


@mcp.tool()
async def debug_set_breakpoint(
    object_id: str,
    line: int,
    module_type: str = "CommonModule",
    property_id: str = "",
    condition: str = "",
    hit_condition: str = "",
) -> str:
    """Set a breakpoint in a BSL module.

    Roadmap 260511 §P0.A (2026-05-11): condition + hit_condition support.
    - `condition`: BSL expression, BP fire'ит только если True (RDBG native).
    - `hit_condition`: VS Code DAP syntax `>N`/`>=N`/`<N`/`<=N`/`=N`/`%N`
      (wrapper enforce'ит counter в _handle_command, auto-Continue if не satisfied).

    Args:
        object_id: UUID of metadata object.
        property_id: Optional explicit propertyID UUID. Auto-resolves from module_type.
        line: Line number.
        module_type: CommonModule|ManagerModule|ObjectModule|RecordSetModule|FormModule|CommandModule.
        condition: BSL conditional expression (e.g. `Контрагент.ИНН = "1234567890"`).
        hit_condition: hit-count predicate `>N`/`%N`/`=N`.
    """
    client = _get_client()
    if not client._attached:
        return json.dumps({"error": "Not connected. Call debug_connect first."})
    # Auto-resolve propertyID from MODULE_PROPERTY_IDS when zero/empty (RDBG silently
    # ignores BPs with zero propertyID — see cache/dbgs-rdbg-debug-server.md §11).
    # Re-attach moved out: debug_connect handles initial attach; повторный attach
    # перед каждым set_breakpoint ломает established BP-delivery state в dbgs.exe.
    xml_module_type, property_id = _resolve_property_id(module_type, property_id)
    # B2 §7.5: auto-apply measured deployed↔src offset (calibrate_result).
    line, applied_offset = _apply_line_offset(client, object_id, line)
    result = await client.set_breakpoints(
        module_type=xml_module_type,
        object_id=object_id,
        property_id=property_id,
        lines=[line],
        condition=condition,
        hit_condition=hit_condition,
    )
    return json.dumps(
        {
            "status": "breakpoint_set",
            "object_id": object_id,
            "property_id": property_id,
            "line": line,
            "applied_offset": applied_offset,
            "module_type": module_type,
            "response": result,
        },
        ensure_ascii=False,
        indent=2,
    )


@mcp.tool()
async def debug_set_logpoint(
    object_id: str,
    line: int,
    message_template: str,
    module_type: str = "CommonModule",
    property_id: str = "",
) -> str:
    """Set a logpoint (tracepoint): log + auto-Continue without user-visible halt.

    Roadmap 260511 P0.B. VS Code DAP Logpoint analog: sets a wrapper-side BP,
    on hit renders message_template (with {expr} placeholders evaluated against
    current stack frame), appends JSONL entry to data/debug_logs/<session>.jsonl,
    then auto-Continue.

    SECURITY: {expr} placeholders в message_template исполняются как BSL-выражения
    в running rphost через client.evaluate (privileged operation, has full access
    to BSL execution context). Не передавайте untrusted templates.

    Args:
        object_id: UUID of metadata object.
        line: Line number.
        message_template: e.g. "ИНН={Контрагент.ИНН} flag={Флаг}".
        module_type: CommonModule|ManagerModule|ObjectModule|RecordSetModule|FormModule|CommandModule.
        property_id: Optional explicit propertyID UUID.
    """
    client = _get_client()
    if not client._attached:
        return json.dumps({"error": "Not connected. Call debug_connect first."})
    xml_module_type, property_id = _resolve_property_id(module_type, property_id)
    # B2 §7.5: auto-apply measured deployed↔src offset (calibrate_result).
    line, applied_offset = _apply_line_offset(client, object_id, line)
    await client.set_breakpoints(
        module_type=xml_module_type,
        object_id=object_id,
        property_id=property_id,
        lines=[line],
        logpoint_template=message_template,
    )
    return json.dumps(
        {
            "status": "logpoint_set",
            "object_id": object_id,
            "property_id": property_id,
            "line": line,
            "applied_offset": applied_offset,
            "module_type": module_type,
            "message_template": message_template,
            "log_path": str(client._log_dir / f"{getattr(client, 'session_id', 'unknown')}.jsonl"),
            "placeholders": logpoints.extract_placeholders(message_template),
        },
        ensure_ascii=False,
        indent=2,
    )


@mcp.tool()
async def debug_step(action: str = "Continue", target_id: str = "") -> str:
    """Control execution: Continue, Step (over), StepIn, StepOut.

    Args:
        action: Continue | Step | StepIn | StepOut
        target_id: UUID from debug_targets. If empty, использует ping
            cached state (P1.3) или fallback на get_targets pull.
    """
    client = _get_client()
    target_id, _ = await _resolve_stopped_target(client, target_id)
    if not target_id:
        return json.dumps({"error": "No stopped targets"})
    result = await client.step(action=action, target_uuid=target_id)
    return json.dumps(
        {"action": action, "target_id": target_id, "result": result}, ensure_ascii=False, indent=2
    )


# ---------------------------------------------------------------------------
# Diagnostic tools (roadmap §4.4 P2.4)
# ---------------------------------------------------------------------------


@mcp.tool()
async def debug_get_breakpoints() -> str:
    """List currently registered breakpoints (client-side cache).

    Roadmap §4.4 P2.4: RDBG не expose'ит server-side getBreakpoints URL,
    поэтому wrapper ведёт local cache по каждому successful set_breakpoint
    call. Используется для verification что BPs реально применились.
    """
    client = _get_client()
    bps = await client.get_breakpoints()
    return json.dumps({"breakpoints": bps, "count": len(bps)}, ensure_ascii=False, indent=2)


@mcp.tool()
async def debug_attach_targets(target_ids: list[str], attach: bool = True) -> str:
    """Explicitly attach (or detach) debug targets to current Debug UI session.

    Roadmap §4.4 P2.4: troubleshooting tool на случай если ping event-loop
    пропустил `targetStarted` event и BPs не fire'ят на каком-то rphost.

    Args:
        target_ids: список UUIDs (получить через debug_targets)
        attach: True = attach (default), False = detach
    """
    client = _get_client()
    if not client._attached:
        return json.dumps({"error": "Not connected. Call debug_connect first."})
    try:
        await client.attach_debug_targets(target_ids, attach=attach)
        if attach:
            client._known_attached_targets.update(target_ids)
        else:
            for tid in target_ids:
                client._known_attached_targets.discard(tid)
        return json.dumps(
            {
                "status": "ok",
                "action": "attach" if attach else "detach",
                "target_ids": target_ids,
                "count": len(target_ids),
            },
            ensure_ascii=False,
            indent=2,
        )
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, ensure_ascii=False)


@mcp.tool()
async def debug_arm_warm_rphosts(target_types: Optional[list[str]] = None) -> str:
    """P0.F roadmap 260511: arm warm-pool rphosts for autonomous BP fire.

    1С ragent holds a warm pool of rphost workers. HTTPService triggers (e.g.
    1c-mcp-crud execute_code) reuse these warm rphosts instead of spawning
    fresh ones — so BPs registered post-spawn never reach them (RDBG attach
    is one-shot at spawn).

    This tool lists all current targets, filters to specified types, attaches
    each to current Debug UI session, marks them as `_attached_pending` (so
    P0.E drain applies on next halt), then re-applies BP workspace.

    Args:
        target_types: filter list. None (default) → ["HTTPService","JOB","Server"].
            Pass empty list `[]` to arm ALL targets unconditionally (no filter).
    """
    client = _get_client()
    if not client._attached:
        return json.dumps({"error": "Not connected. Call debug_connect first."})
    if target_types is None:
        target_types = ["HTTPService", "JOB", "Server"]
    try:
        all_targets = await client.get_targets()
    except Exception as e:
        return json.dumps({"status": "error", "error": f"get_targets failed: {e}"})
    armed = []
    for t in all_targets:
        ttype = t.get("targetType", "")
        if target_types and ttype not in target_types:
            continue
        tid = t.get("id", "")
        if not tid:
            continue
        try:
            await client.attach_debug_targets([tid], attach=True)
            client._known_attached_targets.add(tid)
            client._attached_pending.add(tid)
            armed.append({"id": tid, "type": ttype})
        except Exception as e:
            log.warning("[P0.F] arm failed for target=%s: %s", tid[:8], e)
    reapplied_ok = False
    if armed and client._set_breakpoints_cache:
        try:
            await client._reapply_bp_workspace()
            reapplied_ok = True
        except Exception as e:
            log.warning("[P0.F] BP re-apply after arm failed: %s", e)
    return json.dumps(
        {
            "status": "armed",
            "count": len(armed),
            "filter_types": target_types,
            "armed_targets": armed,
            "bp_workspace_reapplied": reapplied_ok,
        },
        ensure_ascii=False,
        indent=2,
    )


@mcp.tool()
async def debug_arm_next_rphost() -> str:
    """P0.G roadmap 260511: silently arm next rphost (incl. warm pool) for BP fire.

    HTTPService warm-pool rphost is invisible to a new debug session — RDBG only
    auto-attaches NEWLY spawned targets via DBGUIExtCmdInfoStarted. P0.F's
    `debug_arm_warm_rphosts` only sees targets exposed by getDbgAllTargetStates
    (excludes warm pool). This tool uses RDBG global `setBreakOnNextStatement`
    to force-halt the next BSL statement on ANY rphost (including warm pool),
    then the wrapper drains the halt silently — attaches the target + reapplies
    BPs + Continue — making it BP-receptive for the rest of its lifetime.

    Usage:
        debug_connect → set BPs → debug_arm_next_rphost → execute_code → BP fires
    """
    client = _get_client()
    if not client._attached:
        return json.dumps({"error": "Not connected. Call debug_connect first."})
    await client.set_break_on_next_statement(silent=True)
    return json.dumps(
        {
            "status": "silent_arm_armed",
            "next_stop_will_be_drained": True,
            "hint": "Trigger BSL (e.g. execute_code). Wrapper will attach the rphost silently; subsequent BPs/logpoints fire normally.",
        },
        ensure_ascii=False,
        indent=2,
    )


@mcp.tool()
async def debug_capture_mode(on: bool = True) -> str:
    """Sticky capture-mode (#1, 2026-06-03): reliably catch BPs in fast background JOBs.

    Problem: `debug_arm_next_rphost` arms `setBreakOnNextStatement` ONE-SHOT — only the
    first spawned target halts. A short-lived JOB rphost (execute_code →
    ФоновыеЗадания.Выполнить, lives <100ms) races: it can spawn → run past the target
    line → quit before the polled targetStarted handler attaches + applies BPs, so
    `callStackFormed` never arrives. Re-arming after each drain is manual & racy.

    Fix: capture-mode keeps break-on-next **re-armed after every drain**, so EVERY new
    target halts at its first BSL statement; the wrapper then drains (attach + reapply
    BP workspace + brief wait + Continue) and re-arms for the next. Result: each JOB is
    BP-receptive deterministically — no race. Real BP hits (stopByBP=true) are NOT
    drained (kept visible). Turn OFF when done — until then ALL new targets pay the
    spawn-halt cost.

    Usage:
        debug_connect → debug_set_breakpoint → debug_capture_mode(on=True)
        → execute_code (background JOB) → debug_ping → BP fires
        → inspect → debug_step(Continue) → debug_capture_mode(on=False)

    Args:
        on: True — enable + arm immediately; False — disable (also clears pending arm).
    """
    client = _get_client()
    if not client._attached:
        return json.dumps({"error": "Not connected. Call debug_connect first."})
    client._capture_mode = bool(on)
    if on:
        await client.set_break_on_next_statement(silent=True)
        return json.dumps(
            {
                "status": "capture_mode_on",
                "armed": True,
                "hint": "Every new target now halts at its first statement until BPs apply. "
                "Trigger your code, debug_ping, then debug_capture_mode(on=False) to stop.",
            },
            ensure_ascii=False,
            indent=2,
        )
    client._break_on_next_silent_arm = False
    return json.dumps({"status": "capture_mode_off", "armed": False}, ensure_ascii=False, indent=2)


@mcp.tool()
async def debug_coverage_register(lines: list[dict]) -> str:
    """P1.A roadmap 260511: register BSL lines for code coverage tracking.

    Each entry registered as a silent coverage BP — on fire, wrapper increments
    hit counter + auto-Continues (no user-visible halt, no JSONL noise).

    Args:
        lines: list of `{object_id, line, module_type?, property_id?, file_path?}`
            - module_type auto-resolves propertyID via MODULE_PROPERTY_IDS
            - file_path used in genericCoverage.xml output (optional)

    Returns: `{status, registered_count, sample}` JSON envelope.
    """
    client = _get_client()
    if not client._attached:
        return json.dumps({"error": "Not connected. Call debug_connect first."})
    registered = []
    for spec in lines:
        oid = spec.get("object_id", "")
        if not oid:
            continue
        line = spec.get("line", 0)
        module_type = spec.get("module_type", "CommonModule")
        xml_mt, pid = _resolve_property_id(module_type, spec.get("property_id", ""))
        fp = spec.get("file_path", "")
        bsl_coverage.register_line(client, oid, pid, line, fp)
        # Register as BP via existing aggregation (no condition, no template)
        await client.set_breakpoints(
            module_type=xml_mt,
            object_id=oid,
            property_id=pid,
            lines=[int(line)],
        )
        registered.append({"object_id": oid, "line": int(line), "property_id": pid})
    return json.dumps(
        {
            "status": "registered",
            "registered_count": len(registered),
            "sample": registered[:5],
        },
        ensure_ascii=False,
        indent=2,
    )


@mcp.tool()
async def debug_coverage_export(output_path: str = "") -> str:
    """P1.A roadmap 260511: export coverage as SonarQube genericCoverage.xml.

    Args:
        output_path: where to write XML (default: `data/debug_coverage/<session>.xml`)

    Returns: `{path, files_count, lines_total, lines_covered, coverage_pct}` JSON.
    """
    client = _get_client()
    if not client._attached:
        return json.dumps({"error": "Not connected. Call debug_connect first."})
    if not output_path:
        out_dir = Path(__file__).parent / "data" / "debug_coverage"
        out_dir.mkdir(parents=True, exist_ok=True)
        sess = getattr(client, "session_id", None) or "unknown"
        output_path = str(out_dir / f"{sess}.xml")
    result = bsl_coverage.export_generic_coverage_xml(client, output_path)
    return json.dumps(result, ensure_ascii=False, indent=2)


@mcp.tool()
async def debug_calibrate_lines(
    object_id: str,
    line: int,
    module_type: str = "CommonModule",
    property_id: str = "",
    radius: int = 8,
) -> str:
    """Калибровка строк живой конфигурации: silent-веер BP вокруг целевой строки.

    Живой факт 2026-07-07 (гкс_АсинхронныеСервисы): номера строк repo/EDT-src
    систематически смещены относительно deployed-конфигурации → BP по строке
    из git-src молча не fire'ит. Этот tool ставит coverage-BP (hit + auto-
    Continue, без user-visible halt) на диапазон [line-radius, line+radius];
    после триггера кода `debug_calibrate_result` возвращает РЕАЛЬНО исполняемые
    строки и смещение — точечный BP/logpoint ставится уже по ним.

    Workflow:
        debug_calibrate_lines → trigger (ФоновыеЗадания.Выполнить через
        execute_code) → debug_ping ×2-3 → debug_calibrate_result

    Args:
        object_id: UUID metadata-объекта.
        line: целевая строка по локальным исходникам (repo/EDT).
        module_type: CommonModule|ManagerModule|ObjectModule|RecordSetModule|FormModule|CommandModule.
        property_id: явный propertyID (авто-резолв из module_type если пуст).
        radius: полуширина веера (1..30, default 8).
    """
    client = _get_client()
    if not client._attached:
        return json.dumps({"error": "Not connected. Call debug_connect first."})
    xml_module_type, property_id = _resolve_property_id(module_type, property_id)
    line = max(1, int(line))
    radius = max(1, min(int(radius), 30))
    fan = list(range(max(1, line - radius), line + radius + 1))
    if not hasattr(client, "_calibrations"):
        client._calibrations = {}
    stale = client._calibrations.pop(object_id, None)
    if stale:
        # повторная калибровка того же объекта: снять старый веер, иначе его
        # silent auto-Continue BP живут до disconnect (утечка)
        stale_set = set(stale["lines"])
        stale_tracked = getattr(client, "_coverage_tracked", {}) or {}
        for ln in stale["lines"]:
            stale_tracked.pop((object_id, stale["property_id"], ln), None)
        for ce in list(client._set_breakpoints_cache):
            if ce["object_id"] == object_id and ce["property_id"] == stale["property_id"]:
                ce["lines"] = [L for L in ce["lines"] if L not in stale_set]
                if not ce["lines"]:
                    client._set_breakpoints_cache.remove(ce)
    for ln in fan:
        bsl_coverage.register_line(client, object_id, property_id, ln)
    await client.set_breakpoints(
        module_type=xml_module_type,
        object_id=object_id,
        property_id=property_id,
        lines=fan,
    )
    client._calibrations[object_id] = {
        "requested_line": int(line),
        "lines": fan,
        "property_id": property_id,
        "module_type": module_type,
        "xml_module_type": xml_module_type,
    }
    return json.dumps(
        {
            "status": "calibration_armed",
            "object_id": object_id,
            "requested_line": int(line),
            "range": [fan[0], fan[-1]],
            "count": len(fan),
            "next_steps": [
                'Trigger: execute_code → ФоновыеЗадания.Выполнить("Модуль.Метод", Параметры)',
                "debug_ping ×2-3 (пока не увидишь callStackFormed / коду дадут пройти)",
                "debug_calibrate_result(object_id) → реальные строки + offset",
            ],
        },
        ensure_ascii=False,
        indent=2,
    )


@mcp.tool()
async def debug_calibrate_result(
    object_id: str = "",
    clear: bool = True,
    keep_bp_on_nearest: bool = True,
) -> str:
    """Результат калибровки строк: какие строки веера реально исполнились.

    Возвращает fired-строки (hits>0 из coverage-трекера), ближайшую к
    запрошенной и offset (реальная − запрошенная) — типовой сдвиг применим
    ко всему модулю. По умолчанию чистит веер (coverage-ключи + BP workspace)
    и оставляет ОДИН обычный BP на ближайшей fired-строке (уже без auto-
    Continue — следующий проход остановится видимо).

    Args:
        object_id: UUID из debug_calibrate_lines (пусто = все активные калибровки).
        clear: снять веер после чтения результата.
        keep_bp_on_nearest: оставить точечный BP на ближайшей fired-строке.
    """
    client = _get_client()
    if not client._attached:
        return json.dumps({"error": "Not connected. Call debug_connect first."})
    calibs = getattr(client, "_calibrations", {}) or {}
    if object_id:
        calibs = {k: v for k, v in calibs.items() if k == object_id}
    if not calibs:
        return json.dumps(
            {
                "error": "no active calibration",
                "hint": "debug_calibrate_lines first",
            },
            ensure_ascii=False,
        )
    tracked = getattr(client, "_coverage_tracked", {}) or {}
    results = []
    for oid, meta in calibs.items():
        pid = meta["property_id"]
        requested = meta["requested_line"]
        fired = sorted(
            ln for ln in meta["lines"] if tracked.get((oid, pid, ln), {}).get("hits", 0) > 0
        )
        nearest = min(fired, key=lambda L: abs(L - requested)) if fired else None
        entry = {
            "object_id": oid,
            "requested_line": requested,
            "fired_lines": fired,
            "nearest_fired": nearest,
            "offset": (nearest - requested) if nearest is not None else None,
        }
        if not fired:
            entry["hint"] = (
                "веер не сработал: проверь trigger (JOB, не "
                "HTTP-service), pre-existing rphost, radius"
            )
        results.append(entry)
        # B2 §7.5: record measured offset so future BPs on git lines auto-shift.
        if entry["offset"]:
            if not hasattr(client, "_line_offsets"):
                client._line_offsets = {}
            client._line_offsets[oid] = int(entry["offset"])
            _persist_active_session(client)
        if clear:
            fan_set = set(meta["lines"])
            for ln in meta["lines"]:
                tracked.pop((oid, pid, ln), None)
            nearest_kept = False
            for cache_entry in list(client._set_breakpoints_cache):
                if cache_entry["object_id"] == oid and cache_entry["property_id"] == pid:
                    kept = [L for L in cache_entry["lines"] if L not in fan_set]
                    if keep_bp_on_nearest and nearest is not None:
                        kept.append(nearest)
                        nearest_kept = True
                    cache_entry["lines"] = sorted(set(kept))
                    if not cache_entry["lines"]:
                        client._set_breakpoints_cache.remove(cache_entry)
            if keep_bp_on_nearest and nearest is not None and not nearest_kept:
                # кэш мог не содержать веер (HMR-restart) — создаём запись явно
                client._set_breakpoints_cache.append(
                    {
                        "module_type": meta["xml_module_type"],
                        "object_id": oid,
                        "property_id": pid,
                        "lines": [nearest],
                        "ext_id": 0,
                        "url": "",
                        "extension_name": "",
                        "version": "",
                        "condition": "",
                    }
                )
            client._calibrations.pop(oid, None)
    if clear:
        if client._set_breakpoints_cache:
            await client._reapply_bp_workspace()
        else:
            # workspace REPLACES per call — пустой push снимает остатки веера
            body = _build_request(client._base_fields(), _rdbg("bpWorkspace", ""))
            await client._post("setBreakpoints", body)
    return json.dumps(
        {
            "status": "calibration_result",
            "results": results,
            "cleared": bool(clear),
            "bp_kept_on_nearest": bool(keep_bp_on_nearest),
        },
        ensure_ascii=False,
        indent=2,
    )


@mcp.tool()
async def debug_session_record(enable: bool = True) -> str:
    """P2.A roadmap 260511: toggle session snapshot recording.

    When enabled, every user-visible stop event (BP fire / exception not filtered)
    appends snapshot entry to `data/debug_replays/<session>.jsonl`. Entry shape:
    `{ts, iso, session_id, target_id, reason, stack, exception?}`.

    NOT true time-travel — snapshots are read-only post-mortem inspection. Use
    `debug_replay_seek(index)` / `debug_replay_list()` для retrieval.

    Args:
        enable: True (default) — start recording. False — stop recording.
    """
    client = _get_client()
    if not client._attached:
        return json.dumps({"error": "Not connected. Call debug_connect first."})
    client._recording_enabled = bool(enable)
    return json.dumps(
        {
            "status": "recording_enabled" if enable else "recording_disabled",
            "recording_enabled": client._recording_enabled,
            "session_id": getattr(client, "session_id", None),
        },
        ensure_ascii=False,
        indent=2,
    )


@mcp.tool()
async def debug_replay_list() -> str:
    """P2.A roadmap 260511: list snapshots recorded in current session.

    Returns array of `{index, iso, target_id, reason, line, has_exception}`.
    """
    client = _get_client()
    if not client._attached:
        return json.dumps({"error": "Not connected. Call debug_connect first."})
    sess = getattr(client, "session_id", None)
    snapshots = snapshot.list_snapshots(sess) if sess else []
    return json.dumps(
        {
            "session_id": sess,
            "count": len(snapshots),
            "snapshots": snapshots,
        },
        ensure_ascii=False,
        indent=2,
    )


@mcp.tool()
async def debug_replay_seek(index: int) -> str:
    """P2.A roadmap 260511: retrieve full snapshot at given index.

    Returns full entry: `{ts, iso, session_id, target_id, reason, stack, exception?}`
    or `{error: "out of range"}`.
    """
    client = _get_client()
    if not client._attached:
        return json.dumps({"error": "Not connected. Call debug_connect first."})
    sess = getattr(client, "session_id", None)
    entry = snapshot.seek_snapshot(sess, index) if sess else None
    if entry is None:
        return json.dumps(
            {"error": "out of range", "index": index, "session_id": sess},
            ensure_ascii=False,
            indent=2,
        )
    return json.dumps(entry, ensure_ascii=False, indent=2)


@mcp.tool()
async def debug_set_exception_bp(message_pattern: str = "", module_pattern: str = "") -> str:
    """P3.B roadmap 260511: add filter for exception BPs.

    Wrapper's `_handle_command(rteProcessing)` halts on unhandled exceptions.
    Without filters — halts on ALL exceptions (default). With filters — halts
    only if at least one filter matches the exception.

    Each filter has 2 axes (both case-insensitive substring match, empty = "match any"):
    - `message_pattern`: matched against `messageText` of the exception
    - `module_pattern`: matched against top stack frame's `presentation` field

    Args:
        message_pattern: e.g. "ошибка проведения" or "deadlock"
        module_pattern: e.g. "гкс_ДокументРегистрации" or "ОбщегоНазначения"

    Multiple `debug_set_exception_bp` calls accumulate filters (OR semantics —
    halt if ANY filter matches). Use `debug_clear_exception_bps` to reset.
    """
    client = _get_client()
    if not client._attached:
        return json.dumps({"error": "Not connected. Call debug_connect first."})
    f = {"message_pattern": message_pattern, "module_pattern": module_pattern}
    client._exception_bp_filters.append(f)
    return json.dumps(
        {
            "status": "filter_added",
            "filter": f,
            "total_filters": len(client._exception_bp_filters),
        },
        ensure_ascii=False,
        indent=2,
    )


@mcp.tool()
async def debug_clear_exception_bps() -> str:
    """P3.B roadmap 260511: clear all exception BP filters → default (halt on ALL exceptions)."""
    client = _get_client()
    if not client._attached:
        return json.dumps({"error": "Not connected. Call debug_connect first."})
    cleared = len(client._exception_bp_filters)
    client._exception_bp_filters.clear()
    return json.dumps(
        {"status": "cleared", "filters_removed": cleared}, ensure_ascii=False, indent=2
    )


@mcp.tool()
async def debug_list_exception_bps() -> str:
    """P3.B roadmap 260511: list current exception BP filters."""
    client = _get_client()
    if not client._attached:
        return json.dumps({"error": "Not connected. Call debug_connect first."})
    return json.dumps(
        {
            "filters": list(client._exception_bp_filters),
            "count": len(client._exception_bp_filters),
            "default_behavior": "halt-all" if not client._exception_bp_filters else "filter-only",
        },
        ensure_ascii=False,
        indent=2,
    )


@mcp.tool()
async def debug_break_on_next() -> str:
    """Force-break next BSL statement on any rphost (covers pre-existing targets).

    Background: getDbgAllTargetStates returns only targets attached to the
    current debug UI session; rphosts spawned BEFORE debug_connect are
    invisible because targetStarted events do not replay. As a result BPs
    set on existing rphosts never fire. setBreakOnNextStatement is RDBG's
    global op that bypasses this — the next BSL statement on any eligible
    target stops, fires a callStackFormed event, and the wrapper auto-
    attaches that target via the normal handler. After capture you can set
    a precise BP and resume with debug_step("Continue") to land on it on
    a subsequent execution.

    No args. Returns status + reminder to debug_targets after stop event.
    """
    client = _get_client()
    if not client._attached:
        return json.dumps({"error": "Not connected. Call debug_connect first."})
    try:
        await client.set_break_on_next_statement()
        return json.dumps(
            {
                "status": "ok",
                "action": "break_on_next_statement_armed",
                "next_step": (
                    "Trigger any BSL execution; then debug_targets to see "
                    "captured target; then set precise BP + debug_step Continue."
                ),
            },
            ensure_ascii=False,
            indent=2,
        )
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, ensure_ascii=False)


@mcp.tool()
async def debug_launch_thin_client(
    infobase_alias: str = "",
    user: str = "",
    password: str = "",
    server: str = "localhost:1541",
    debugger_url: str = "http://localhost:1550",
    wait_target_timeout_sec: int = 15,
) -> str:
    """Launch 1cv8c.exe (thin client) с правильными /Debug -http /DebuggerURL флагами.

    Roadmap 260511 §3.5 (P1). Auto-flagged thin client launch closes RC3
    (protocol mismatch tcp:// vs http://) and provides Solution C как
    first-class workflow вместо manual workaround.

    Args:
        infobase_alias: cluster IB name (mandatory если пуст — error)
        user: optional /N username
        password: optional /P password (be careful with secrets in logs)
        server: cluster server (default localhost:1541)
        debugger_url: debug agent URL (default http://localhost:1550)
        wait_target_timeout_sec: timeout для ожидания регистрации target'а

    Returns: {status, pid, command_line, target_registered, first_target_id,
              elapsed_ms}
    """
    import os
    import subprocess as sp

    if not infobase_alias:
        return json.dumps(
            {"status": "error", "reason": "infobase_alias_required"}, ensure_ascii=False, indent=2
        )
    exe = _find_1cv8c_exe()
    if not exe:
        return json.dumps(
            {
                "status": "error",
                "reason": "1cv8c_exe_not_found",
                "searched": list(_1CV8C_BIN_CANDIDATES),
                "hint": "Provide explicit path via env or install 1С platform",
            },
            ensure_ascii=False,
            indent=2,
        )
    # Validate infobase_alias unless cluster unreachable
    validation = _validate_infobase_alias(infobase_alias)
    if validation["status"] == "invalid":
        return json.dumps(
            {
                "status": "error",
                "reason": "infobase_alias_not_found",
                "provided": infobase_alias,
                "available": validation["available"],
            },
            ensure_ascii=False,
            indent=2,
        )
    args = [exe, f"/S{server}\\{infobase_alias}", "/Debug", "-http", f"/DebuggerURL={debugger_url}"]
    if user:
        args.extend(["/N", user])
    if password:
        args.extend(["/P", password])
    try:
        # Detached background launch (Windows) — DETACHED_PROCESS=0x00000008
        creationflags = getattr(sp, "DETACHED_PROCESS", 0) | getattr(
            sp, "CREATE_NEW_PROCESS_GROUP", 0
        )
        proc = sp.Popen(
            args,
            creationflags=creationflags,
            stdin=sp.DEVNULL,
            stdout=sp.DEVNULL,
            stderr=sp.DEVNULL,
            close_fds=True,
        )
    except (OSError, sp.SubprocessError) as e:
        return json.dumps(
            {"status": "error", "reason": "launch_failed", "error": str(e)},
            ensure_ascii=False,
            indent=2,
        )
    # Wait for target registration via existing client (if connected)
    target_registered = False
    first_target_id = None
    elapsed_ms = 0
    not_connected_warning = None
    if _client and _client._attached:
        import time as _t

        start = _t.monotonic()
        timeout = max(1, min(60, wait_target_timeout_sec))
        while _t.monotonic() - start < timeout:
            try:
                targets = await _client.get_targets()
            except Exception:
                targets = []
            if targets:
                target_registered = True
                first_target_id = next((t.get("id") for t in targets if t.get("id")), None)
                break
            await asyncio.sleep(0.5)
        elapsed_ms = int((_t.monotonic() - start) * 1000)
    else:
        not_connected_warning = (
            "Not connected to debug agent — target_registered detection "
            "skipped. Call debug_connect first для polling."
        )
    # Hide password в command_line на возврате
    command_line_safe = " ".join(
        ("/P***" if arg == password and password else f'"{arg}"' if " " in arg else arg)
        for arg in args
    )
    response = {
        "status": "ok" if target_registered else "launched",
        "pid": proc.pid,
        "command_line": command_line_safe,
        "target_registered": target_registered,
        "first_target_id": first_target_id,
        "elapsed_ms": elapsed_ms,
        "note": (
            "Target not yet registered — perform any action в GUI "
            "to trigger BSL execution, then debug_wait_for_target"
            if not target_registered
            else None
        ),
    }
    if not_connected_warning:
        response["warning"] = not_connected_warning
    if password:
        response["security_note"] = (
            "/P password передаётся через CLI argv — виден в OS process list "
            "(Get-Process | Select CommandLine). НЕ использовать в shared/"
            "production контекстах. Предпочтительно: сохранённые credentials "
            "в Windows-storage клиента или Windows-auth."
        )
    return json.dumps(response, ensure_ascii=False, indent=2)


@mcp.tool()
async def debug_wait_for_target(timeout_sec: int = 10, poll_interval_sec: float = 0.5) -> str:
    """Block until ≥1 target appears in debug_targets, or timeout.

    Roadmap 260511 §3.4 (P1). Synchronous primitive для guaranteed-attached
    workflow: после debug_connect / launch_thin_client часто требуется
    дождаться регистрации target'а (rphost spawn + DBGUIExtCmdInfoStarted
    handler) перед set_breakpoint.

    Args:
        timeout_sec: max wait time. Clamped to [1, 60].
        poll_interval_sec: pause между debug_targets polls.

    Returns: {status: "ok"|"timeout", targets_count, first_target_id,
              elapsed_ms, [suggestion if timeout]}
    """
    import time as _t

    timeout_sec = max(1, min(60, timeout_sec))
    client = _get_client()
    if not client._attached:
        return json.dumps(
            {"error": "Not connected. Call debug_connect first."}, ensure_ascii=False, indent=2
        )
    start = _t.monotonic()
    while _t.monotonic() - start < timeout_sec:
        try:
            targets = await client.get_targets()
        except Exception:
            targets = []
        if targets:
            first_id = next((t.get("id") for t in targets if t.get("id")), None)
            return json.dumps(
                {
                    "status": "ok",
                    "targets_count": len(targets),
                    "first_target_id": first_id,
                    "elapsed_ms": int((_t.monotonic() - start) * 1000),
                },
                ensure_ascii=False,
                indent=2,
            )
        await asyncio.sleep(poll_interval_sec)
    return json.dumps(
        {
            "status": "timeout",
            "targets_count": 0,
            "first_target_id": None,
            "elapsed_ms": int((_t.monotonic() - start) * 1000),
            "suggestion": (
                "No targets registered within timeout. Try: (1) launch thin "
                "client with /Debug -http /DebuggerURL=http://localhost:1550, "
                "(2) trigger BSL via execute_code, (3) check infobase_alias "
                "valid via debug_health_check, (4) try recycle_strategy="
                "all_rphosts_of_ib if pre-existing rphost gap."
            ),
        },
        ensure_ascii=False,
        indent=2,
    )


@mcp.tool()
async def debug_target_state(target_id: str = "") -> str:
    """Get state of a single debug target (or current Debug UI session).

    Roadmap §4.4 P2.4 diagnostic. Если target_id пуст — возвращает
    wrapper-side snapshot Debug UI session (infobase_alias, session_id,
    attached, known/stopped targets) без RDBG roundtrip. Real-world finding
    2026-05-09 (RDBG 8.3.27.1936): `getDbgTargetState` без targetID
    возвращает HTTP 400 «Не указан идентификатор предмета отладки», поэтому
    session-state делается локально, а не запросом к RDBG.

    Если target_id передан — resolve через get_targets() (per-target single-
    state endpoint имеет undocumented contract — фильтрация безопаснее).

    Args:
        target_id: UUID цели или пусто для wrapper-side session snapshot.
    """
    client = _get_client()
    if not client._attached:
        return json.dumps({"error": "Not connected. Call debug_connect first."})
    state = await client.get_target_state(target_uuid=target_id or None)
    return json.dumps(
        {"target_id": target_id or None, "state": state}, ensure_ascii=False, indent=2
    )


def _cli_main() -> int:
    """Fix #6 §12.8 — CLI runner для debug tools без MCP reload.

    Каждый subcommand = fresh Python process import = no /mcp reconnect нужен
    при изменении wrapper'а. Useful для итеративной разработки.

    Subcommands map 1-to-1 на @mcp.tool()-decorated functions:
        health-check, session-summary, session-diff, ping, targets,
        target-state, get-breakpoints (read-only)

    Mutating tools (connect, set-breakpoint, evaluate, step, disconnect)
    оставлены только в MCP режиме — они требуют persistent _client state
    между вызовами который не имеет смысла в CLI per-process модели.

    Usage:
        python mcp_debug_server.py health-check
        python mcp_debug_server.py session-summary --format markdown
        python mcp_debug_server.py session-diff --prev <uuid> [--curr <uuid>]
    """
    import argparse

    # Force UTF-8 stdout для Windows cp1251 default (Cyrillic + math symbols)
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, OSError):
        pass
    parser = argparse.ArgumentParser(description="1С Debug Server CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("health-check", help="Run debug_health_check probe (read-only)")

    p_summary = sub.add_parser(
        "session-summary", help="Print session summary by session_id или current"
    )
    p_summary.add_argument("--format", default="json", choices=("json", "markdown"))

    p_diff = sub.add_parser(
        "session-diff", help="Diff 2 persisted sessions для regression detection"
    )
    p_diff.add_argument("--prev", required=True, help="prev session UUID")
    p_diff.add_argument("--curr", default=None, help="curr session UUID (default: current)")

    args = parser.parse_args()

    if args.cmd == "health-check":
        result = asyncio.run(debug_health_check())
    elif args.cmd == "session-summary":
        result = asyncio.run(debug_session_summary(format=args.format))
    elif args.cmd == "session-diff":
        result = asyncio.run(
            debug_session_diff(prev_session_id=args.prev, curr_session_id=args.curr)
        )
    else:
        parser.print_help()
        return 2
    print(result)
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("health-check", "session-summary", "session-diff"):
        sys.exit(_cli_main())
    mcp.run()
