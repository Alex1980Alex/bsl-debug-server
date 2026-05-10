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
from typing import Optional

import httpx
from mcp.server.fastmcp import FastMCP

# Local modules — UUID → path resolution + BSL local-name extraction
import bsl_locals
import uuid_index

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
    "CommonModule":  "d5963243-262e-4398-b4d7-fb16d06484f6",
    "ManagerModule": "d1b64a2c-8078-4982-8190-8f81aefda192",
    "ObjectModule":  "a637f77f-3840-441d-a1c3-699c8c5cb7e0",
    "RecordSetModule": "9f36fd70-4bf4-47f6-b235-935f73aab43f",
    "FormModule":    "32e087ab-1491-49b6-aba7-43571b41ac2b",
    "CommandModule": "078a6af8-d22c-4248-9c33-7e90075a3d2c",
}
ZERO_UUID = "00000000-0000-0000-0000-000000000000"


def _build_request(*children_xml: str) -> str:
    """Build a JAXB-compatible RDBG XML request string.

    All children_xml strings are inserted raw inside <debugBaseData:request>.
    """
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<debugBaseData:request'
        f' xmlns:debugRDBGRequestResponse="{NS["rdbg"]}"'
        f' xmlns:debugBaseData="{NS["base"]}"'
        f' xmlns:debugCalculations="{NS["calc"]}"'
        f' xmlns:debugAutoAttach="{NS["auto"]}"'
        f' xmlns:debugBreakpoints="{NS["bp"]}"'
        f' xmlns:debugRTEFilter="{NS["rte"]}"'
        ">"
        + "".join(children_xml)
        + "</debugBaseData:request>"
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


def _aggregate_breakpoints(cache: list, new_entry: dict) -> dict:
    """Merge cached BP entries + new entry into per-module groups.

    RDBG `setBreakpoints` команда REPLACES workspace при каждом вызове —
    multi-line BPs одного модуля и multi-module BPs должны идти ОДНИМ
    request'ом (multiple `moduleBPInfo` elements в `bpWorkspace`). Wrapper
    aggregates все cached BPs (плюс new_entry) и каждый submit отправляет
    full workspace, иначе предыдущие BPs теряются (live finding 2026-05-10).

    Returns: dict keyed by 7-tuple
        (module_type, object_id, property_id, ext_id, url, extension_name, version)
    value = sorted list[int] of dedupe'd line numbers.
    """
    grouped: dict = {}
    for entry in list(cache) + [new_entry]:
        key = (
            entry["module_type"], entry["object_id"], entry["property_id"],
            entry.get("ext_id", 0) or 0,
            entry.get("url", "") or "",
            entry.get("extension_name", "") or "",
            entry.get("version", "") or "",
        )
        line_set: set = grouped.setdefault(key, set())
        for line in entry.get("lines", []):
            try:
                line_set.add(int(line))
            except (TypeError, ValueError):
                continue
    return {k: sorted(v) for k, v in grouped.items()}


class RDBGClient:
    """HTTP client for 1C debug agent RDBG protocol (JAXB-compatible)."""

    HEADERS = {
        "Accept": "application/xml",
        "Content-Type": "application/xml; charset=utf-8",
        "User-Agent": "1CV8",
    }

    def __init__(self, debug_url: str = "http://localhost:1550",
                 infobase_alias: str = "DefAlias"):
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
        self._bp_by_location: dict = {}    # "obj_id:line" → fire count
        self._eval_count = 0
        self._eval_failures = 0
        self._eval_errors: list = []       # last N error strings
        self._ui_plus_retry_count = 0
        self._recycle_method_used: Optional[str] = None
        self._force_recycle_invoked = False
        self._stop_events: list = []       # [{ts, target_id, lineNo}]
        self._rphosts_seen: set = set()

    async def _post(self, command: str, body: str,
                    include_dbgui_url: bool = False,
                    _ui_plus_retry: bool = True) -> ET.Element:
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
                and command not in ("initSettings", "clearBreakOnNextStatement",
                                    "attachDebugUI", "detachDebugUI")
                and ("UI+ - \u0447\u0430\u0441\u0442\u044c \u043e\u0442\u043b\u0430\u0434\u043a\u0438 \u043d\u0435 \u0437\u0430\u0440\u0435\u0433\u0438\u0441\u0442\u0440\u0438\u0440\u043e\u0432\u0430\u043d\u0430" in err_body
                     or "UI+ debug part not registered" in err_body)
            )
            if ui_plus_lost:
                return await self._ui_plus_recover_and_retry(
                    command, body, include_dbgui_url, resp, err_body,
                )
            log.error("RDBG %s -> HTTP %s body=%s", command, resp.status_code, err_body)
            raise httpx.HTTPStatusError(
                f"RDBG {command} {resp.status_code}: {err_body}",
                request=resp.request, response=resp,
            )
        text = resp.text.lstrip("\ufeff")
        if not text:
            return ET.Element("empty")
        return ET.fromstring(text)

    async def _ui_plus_recover_and_retry(self, command, body,
                                          include_dbgui_url, failed_resp, err_body):
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
                return await self._post(command, body,
                                         include_dbgui_url=include_dbgui_url,
                                         _ui_plus_retry=False)
            except httpx.HTTPStatusError as light_err:
                if not self._is_ui_plus_lost(light_err):
                    raise
        log.warning("RDBG %s → escalating to full detach+attach", command)
        return await self._ui_plus_full_reattach_and_retry(
            command, body, include_dbgui_url)

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
        return await self._post(command, body,
                                 include_dbgui_url=include_dbgui_url,
                                 _ui_plus_retry=False)

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
        return (
            _rdbg("infoBaseAlias", self.infobase_alias)
            + _rdbg("idOfDebuggerUI", self.session_id)
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
        return {"result": result, "session_id": self.session_id,
                "fully_registered": self._registered}

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
            if (stale_id and stale_id != self.session_id
                    and stale_id != ZERO_UUID):
                log.info("[cleanup_stale] existing debug UI session %s found, "
                         "attempting detach", stale_id[:8])
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

    async def _ping_loop(self) -> None:
        """Periodic ping: keep session alive AND dispatch DBGUIExtCmdInfo events.

        Roadmap §13 (post-BP-fire handshake): mirrors yukon39 Debugee.run()
        dispatch loop. ping() returns list of DBGUIExtCmdInfo* commands;
        each is fed to _handle_command() which auto-attaches new targets,
        caches stack on stop events, etc.

        Sequential await per command (NO asyncio.gather) — preserves event
        ordering. Race condition `targetStarted` + `callStackFormed` для
        одного target обрабатывается корректно: attach-then-cache.
        """
        try:
            while self._attached and self._registered:
                await asyncio.sleep(2.0)
                try:
                    commands = await self.ping()
                    for cmd in commands:
                        try:
                            await self._handle_command(cmd)
                        except Exception as e:
                            log.warning("event handler failed for %s: %s",
                                        cmd.get("cmdId") or cmd.get("_tag"), e)
                except Exception as e:
                    log.debug("ping failed: %s", e)
        except asyncio.CancelledError:
            pass

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
                log.debug("[event] cmdId derived from cmdIDNum=%s -> %s",
                          num, cmd_type)
        # Extract target_id — payload может иметь nested targetID или targetIDStr
        target_id = self._extract_target_id(cmd)

        if cmd_type == "targetStarted":
            # 🔴 CRITICAL: auto-attach NEW targets (rphost при posting документа)
            if target_id and target_id not in self._known_attached_targets:
                try:
                    await self.attach_debug_targets([target_id])
                    self._known_attached_targets.add(target_id)
                    log.info("[event] Started: target %s → attached", target_id[:8])
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
            log.info("[event] CallStackFormed: target=%s frames=%d reason=%s",
                     target_id[:8], len(stack), self._stop_reason_by_target[target_id])
            # §12.3 Level 3 — track stop event для session_summary
            from datetime import datetime as _dt
            top = stack[0] if stack else {}
            line_no = top.get("lineNo", "?") if isinstance(top, dict) else "?"
            obj_id_top = ""
            if isinstance(top, dict):
                mod_id = top.get("moduleID")
                if isinstance(mod_id, dict):
                    obj_id_top = mod_id.get("objectID", "")
            self._stop_events.append({
                "ts": _dt.now().isoformat(),
                "target_id": target_id,
                "lineNo": line_no,
                "reason": self._stop_reason_by_target[target_id],
            })
            self._rphosts_seen.add(target_id)
            if stop_by_bp:
                self._bp_fire_count += 1
                if obj_id_top and line_no != "?":
                    key = f"{obj_id_top}:{line_no}"
                    self._bp_by_location[key] = self._bp_by_location.get(key, 0) + 1

        elif cmd_type == "rteProcessing":
            # 🟠 IMPORTANT: unhandled exception — also a stop event
            if not target_id:
                log.warning("rteProcessing without target_id, skipping")
                return
            self._stopped_targets.add(target_id)
            self._last_stopped_target_id = target_id
            stack_raw = cmd.get("callStack")
            stack = stack_raw if isinstance(stack_raw, list) else \
                    [stack_raw] if isinstance(stack_raw, dict) else []
            self._last_stack_by_target[target_id] = stack
            self._stop_reason_by_target[target_id] = "exception"
            exc = cmd.get("exception")
            if isinstance(exc, dict):
                self._last_exception_by_target[target_id] = exc
            log.warning("[event] RTE: target=%s exception_present=%s frames=%d",
                        target_id[:8], bool(exc), len(stack))

        elif cmd_type == "targetQuit":
            if target_id:
                self._stopped_targets.discard(target_id)
                self._last_stack_by_target.pop(target_id, None)
                self._stop_reason_by_target.pop(target_id, None)
                self._last_exception_by_target.pop(target_id, None)
                self._known_attached_targets.discard(target_id)
                log.info("[event] Quit: target=%s", target_id[:8])

        elif cmd_type == "correctedBP":
            log.warning("[event] BP corrected to adjusted line for target %s",
                        (target_id or "?")[:8])

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
                log.debug("[event] ExprEvaluated for unknown result_id=%s (no pending future)",
                          (result_id or "?")[:8])

        elif cmd_type in ("ForegroundHelperSet", "ForegroundHelperRequest",
                           "ForegroundHelperProcess", "measureResultProcessing",
                           "errorViewInfo", "rteOnBPConditionProcessing",
                           "valueModified", "unknown", ""):
            log.debug("[event] Skipping %s", cmd_type or "<empty>")

        else:
            log.debug("[event] Unrecognised cmdId=%r tag=%r", cmd_type, cmd.get("_tag"))

    _UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)

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

    async def set_auto_attach_settings(
        self, target_types: list[str] | None = None
    ) -> bool:
        """RDBG setAutoAttachSettings — declare which target kinds auto-attach.

        Separate cmd from initSettings (yukon39 Debugee.attach() calls them in
        sequence: initSettings → clearBreakOnNextStatement → setAutoAttach-
        Settings). Default subscribes to Server (rphost) + ManagedClient
        (1cv8c.exe) — covers thin-client + server-side rphost session.
        """
        # Fix #1 ROLLBACK 2026-05-10 (autonomous L2 test detected regression):
        # RDBG returns HTTP 400 «Несоответствие свойства targetType» when XSD
        # enum gets values вне [Server, ManagedClient]. HTTPService/WebService/
        # BackgroundJob — НЕ valid в этой версии XSD. Default revert to safe
        # 2-type set; per-scenario expansion должен передаваться явно через
        # target_types kwarg + проверка XSD'а в roadmap §11.5 follow-up.
        # Note: Server filter всё ещё ловит rphost'ы которые обрабатывают IIS
        # HTTP-services (они тоже rphost workers), но не emit'ят отдельный
        # HTTPService event. Multi-rphost IIS scenario требует force-recycle
        # (Fix #2) для предсказуемого attach.
        types = target_types or ["Server", "ManagedClient"]
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
            return True
        except Exception:
            return False

    async def attach_debug_targets(self, target_uuids: list[str],
                                    attach: bool = True) -> bool:
        """Attach/detach specific debug targets to this session."""
        ids = "".join(_rdbg("id", _target_id_light(uid)) for uid in target_uuids)
        body = _build_request(
            self._base_fields(),
            _rdbg("attach", str(attach).lower()),
            ids,
        )
        await self._post("attachDetachDbgTargets", body)
        return True

    async def set_break_on_next_statement(self) -> bool:
        """RDBG global op — break on next BSL statement on any eligible target.

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
        """Ping for events. Uses dbgui in URL as per Java implementation."""
        body = _build_request(
            _rdbg("idOfDebuggerUI", self.session_id),
        )
        root = await self._post("pingDebugUIParams", body,
                                include_dbgui_url=True)
        return _parse_response(root)

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
            log.debug("[get_call_stack] cache hit target=%s frames=%d",
                      target_uuid[:8], len(cached))
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

    async def eval_local_variables(self, target_uuid: Optional[str] = None,
                                    stack_level: int = 0,
                                    expressions: Optional[list[str]] = None,
                                    async_wait_timeout: float = 10.0,
                                    max_text_size: int = 4096) -> list[dict]:
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
            src_calc_info = (
                _calc("expressionResultID", result_id)
                + _calc("calcItem",
                        _calc("itemType", "expression")
                        + _calc("expression", name))
            )
            expr_blocks.append(_rdbg(
                "expr",
                _calc("stackLevel", str(stack_level))
                + _calc("srcCalcInfo", src_calc_info)
                + _calc("presOptions", _calc("maxTextSize", str(max_text_size))),
            ))
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
                    log.warning("eval_local_variables[%s] timeout after %ss",
                                name, async_wait_timeout)
                    out.append({"name": name, "evalResultState": "timeout"})
            return out
        finally:
            for _, result_id, _ in result_ids:
                self._pending_evals.pop(result_id, None)

    async def eval_locals_auto(self, target_uuid: Optional[str] = None,
                                stack_level: int = 0,
                                async_wait_timeout: float = 10.0,
                                max_text_size: int = 4096) -> list[dict]:
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
            log.info("eval_locals_auto: UUID %s + %s -> no source path",
                     object_id[:8], property_id[:8])
            return []
        names = bsl_locals.extract_locals_at_line(path, line_no)
        if not names:
            log.info("eval_locals_auto: no locals extracted at %s:%d",
                     path.name, line_no)
            return []
        log.info("eval_locals_auto: extracted %d names at %s:%d",
                 len(names), path.name, line_no)
        return await self.eval_local_variables(
            target_uuid=target_uuid,
            stack_level=stack_level,
            expressions=names,
            async_wait_timeout=async_wait_timeout,
            max_text_size=max_text_size,
        )

    async def eval_expression(self, expression: str,
                               target_uuid: Optional[str] = None,
                               stack_level: int = 0,
                               view_interface: Optional[str] = None,
                               max_text_size: int = 4096,
                               async_wait_timeout: float = 10.0) -> list[dict]:
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
        src_calc_info = (
            _calc("expressionResultID", expr_result_id)
            + _calc("calcItem",
                    _calc("itemType", "expression")
                    + _calc("expression", expression))
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
                log.warning("eval_expression timeout for result_id=%s — RDBG didn't deliver "
                            "exprEvaluated event within %ss",
                            expr_result_id[:8], async_wait_timeout)
                return []
        finally:
            self._pending_evals.pop(expr_result_id, None)

    # -- Control API -------------------------------------------------------

    async def step(self, action: str = "Continue",
                   target_uuid: Optional[str] = None) -> list[dict]:
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
            "module_type": module_type, "object_id": object_id,
            "property_id": property_id, "lines": list(lines),
            "ext_id": ext_id, "url": url,
            "extension_name": extension_name, "version": version,
        }
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
            bp_xml = "".join(
                _bp("bpInfo",
                    _bp("line", str(L))
                    + _bp("isActive", "true")
                    + _bp("temp", "false"))
                for L in bp_lines
            )
            module_bp_infos.append(
                _bp("moduleBPInfo", _bp("id", mod_xml) + bp_xml)
            )
        workspace_xml = _rdbg("bpWorkspace", "".join(module_bp_infos))
        body = _build_request(self._base_fields(), workspace_xml)
        root = await self._post("setBreakpoints", body)
        # Reconcile cache from groups (consolidates duplicate entries и
        # сохраняет full state для следующего set call).
        self._set_breakpoints_cache = [
            {
                "module_type": k[0], "object_id": k[1], "property_id": k[2],
                "ext_id": k[3], "url": k[4],
                "extension_name": k[5], "version": k[6],
                "lines": list(v),
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
    global _client
    if _client is None:
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
            capture_output=True, text=True, timeout=5,
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


def _find_rac_exe() -> Optional[str]:
    """Locate rac.exe (1С Remote Administrative Client) on disk."""
    import os
    for path in _RAC_BIN_CANDIDATES:
        if os.path.isfile(path):
            return path
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
        return {"killed": [], "failed": [], "method": "dry_run",
                "would_kill": list(pids),
                "note": "dry_run=True — no subprocess invoked"}
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
            capture_output=True, text=True, timeout=5,
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
            [rac_exe, "process", "list", f"--cluster={cluster}",
             *_rac_auth_args()],
            capture_output=True, text=True, timeout=5,
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


def _recycle_via_rac(rac_exe: str, cluster: str, pids: list,
                     pid_to_uuid: dict) -> dict:
    """Turn off rphost workers через `rac process turn-off` (graceful drain)."""
    killed: list = []
    failed: list = []
    for pid in pids:
        proc_uuid = pid_to_uuid.get(pid)
        if not proc_uuid:
            failed.append({"pid": pid,
                           "error": "no cluster process UUID for this PID"})
            continue
        try:
            result = subprocess.run(
                [rac_exe, "process", "turn-off",
                 f"--cluster={cluster}", f"--process={proc_uuid}",
                 *_rac_auth_args()],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if result.returncode == 0:
                killed.append(pid)
            else:
                err = (result.stderr or result.stdout or "").strip()
                failed.append({"pid": pid,
                               "error": err or f"rac exit={result.returncode}"})
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
    cmd = ("Restart-Service -Name '1C:Enterprise 8.3 Server Agent' "
           "-Force -ErrorAction Stop; Write-Output 'OK'")
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, text=True, timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (subprocess.SubprocessError, OSError) as e:
        return {"killed": [],
                "failed": [{"pid": p, "error": str(e)} for p in pids],
                "method": "service.restart"}
    if result.returncode == 0 and "OK" in (result.stdout or ""):
        return {"killed": list(pids), "failed": [], "method": "service.restart"}
    err = (result.stderr or result.stdout or "").strip()
    return {"killed": [],
            "failed": [{"pid": p, "error": err or f"powershell exit={result.returncode}"}
                       for p in pids],
            "method": "service.restart"}


def _recycle_via_taskkill(pids: list) -> dict:
    """Fallback: hard taskkill /F. SYSTEM-owned rphost → Access Denied."""
    killed: list = []
    failed: list = []
    for pid in pids:
        try:
            result = subprocess.run(
                ["taskkill.exe", "/F", "/PID", str(pid)],
                capture_output=True, text=True, timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if result.returncode == 0:
                killed.append(pid)
            else:
                err = (result.stderr or result.stdout or "").strip()
                failed.append({"pid": pid,
                               "error": err or f"taskkill exit={result.returncode}"})
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
        return {"status": "fail", "detail": f"{host}:{port} not reachable ({e})",
                "fix": "start ragent service with -debug -http flags"}


def _hc_probe_ragent_debug_flag() -> dict:
    """Verify ragent service has -debug + -http flags (Windows-only)."""
    if sys.platform != "win32":
        return {"status": "warn", "detail": "non-Windows — skip"}
    cmd = ('Get-CimInstance Win32_Service -Filter "Name=\'1C:Enterprise 8.3 Server Agent\'" '
           '| Select-Object -ExpandProperty PathName')
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, text=True, timeout=5,
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
    return {"status": "fail", "detail": f"ragent missing flags: {missing}",
            "fix": "scripts/enable-1c-server-debug-http.cmd (run as admin)"}


def _hc_probe_rphost_baseline() -> dict:
    """Count pre-existing rphost.exe processes."""
    rphosts = detect_pre_existing_rphosts()
    if not rphosts:
        return {"status": "pass", "detail": "no pre-existing rphost — fresh env"}
    pids = [r["pid"] for r in rphosts]
    return {"status": "warn",
            "detail": f"{len(pids)} pre-existing rphost(s): {pids}",
            "fix": "kill-stale-rphosts (auto-prepare action)"}


def _hc_probe_rac_available() -> dict:
    """rac.exe found + reachable cluster?"""
    rac = _find_rac_exe()
    if not rac:
        return {"status": "warn", "detail": "rac.exe not found in standard paths",
                "fix": "install 1С platform OR rely on taskkill fallback"}
    cluster = _rac_get_cluster_uuid(rac)
    if not cluster:
        return {"status": "warn",
                "detail": f"rac.exe found at {rac} but cluster unreachable",
                "fix": "check ragent on :1540"}
    return {"status": "pass",
            "detail": f"rac.exe + cluster {cluster[:8]}…"}


def _hc_probe_env_vars() -> dict:
    """Env vars для force_recycle paths."""
    import os
    rac_user = bool(os.environ.get("RAC_CLUSTER_USER", "").strip())
    rac_pwd = bool(os.environ.get("RAC_CLUSTER_PWD", ""))
    svc_restart = (os.environ.get("BSL_DEBUG_ALLOW_SERVICE_RESTART", "")
                   .lower() == "true")
    flags = {
        "RAC_CLUSTER_USER": rac_user, "RAC_CLUSTER_PWD": rac_pwd,
        "BSL_DEBUG_ALLOW_SERVICE_RESTART": svc_restart,
    }
    return {"status": "pass", "detail": f"env: {flags}",
            "_extras": flags}


def _hc_probe_sddl_au_grant() -> dict:
    """SDDL contains AU ACE for Service Stop/Start (Fix #4 enabler)?"""
    if sys.platform != "win32":
        return {"status": "warn", "detail": "non-Windows — skip"}
    try:
        result = subprocess.run(
            ["sc.exe", "sdshow", "1C:Enterprise 8.3 Server Agent"],
            capture_output=True, text=True, timeout=5,
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
    return {"status": "warn",
            "detail": "AU ACE not found — service.restart требует admin",
            "fix": "scripts/grant-1c-debug-permissions.ps1 (run as admin once)"}


def _hc_probe_active_session(client) -> dict:
    """wrapper-side state — есть ли активная debug session?"""
    if client is None or not getattr(client, "_attached", False):
        return {"status": "pass", "detail": "no active debug session"}
    return {"status": "pass",
            "detail": f"attached to {client.infobase_alias}, "
                      f"session={client.session_id[:8]}…"}


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
            [rac, "process", "list", f"--cluster={cluster}",
             *_rac_auth_args()],
            capture_output=True, text=True, timeout=5,
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
        return {"status": "warn",
                "detail": f"high-load rphost(s) >{threshold} conns: {high_load}",
                "fix": "wait for low-load window OR force_recycle (kills active sessions)"}
    return {"status": "pass", "detail": f"all rphost'ы ≤{threshold} connections"}


def _hc_recommend_workflow(checks: dict) -> str:
    """Pick workflow path based on probe results."""
    if checks.get("dbgs_port_1550", {}).get("status") == "fail":
        return "read-only"
    rphost_warn = checks.get("rphost_count_baseline", {}).get("status") == "warn"
    rac_ok = checks.get("rac_exe_path", {}).get("status") == "pass"
    svc_ok = (checks.get("env_vars", {}).get("_extras", {})
              .get("BSL_DEBUG_ALLOW_SERVICE_RESTART") and
              checks.get("sddl_au_grant", {}).get("status") == "pass")
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
    }


# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------
mcp = FastMCP("1c-debug")


@mcp.tool()
async def debug_connect(debug_url: str = "http://localhost:1550",
                        infobase_alias: str = "TestDB",
                        force_recycle_rphost: bool = False) -> str:
    """Connect to 1C debug agent and attach as debug client.

    IMPORTANT: Only ONE debug UI can be active per infobase.
    If EDT is debugging, you'll get 'ibInDebug' (read-only).
    Stop EDT debugging first for full access ('registered').

    Args:
        debug_url: URL of 1C debug agent (default: http://localhost:1550)
        infobase_alias: Infobase name in 1C cluster
        force_recycle_rphost: Solution A from roadmap §11.2. When True,
            after successful attach + setAutoAttachSettings, taskkill /F
            on every rphost.exe alive ДО connect. Ragent then spawns
            fresh worker(s) which read the filter at registration time
            → emit DBGUIExtCmdInfoStarted → wrapper auto-attaches → BPs
            fire on subsequent BSL execution (closes §10 «pre-existing
            rphost invisible» gap). Default False = preflight-warning
            mode (response includes pre_existing_rphost_warning with
            PIDs + next-step suggestions). RISK when True: разрыв
            активных пользовательских сессий в killed rphost'ах.
    """
    global _client
    if _client and _client._attached:
        await _client.close()

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
        recycle_info: Optional[dict] = None
        if force_recycle_rphost and pre_existing_rphosts and _client._registered:
            pids_to_kill = [r["pid"] for r in pre_existing_rphosts]
            # Fix #4 §12.8: env BSL_DEBUG_DRY_RUN_RECYCLE=true → preview only
            import os
            dry_run = (os.environ.get("BSL_DEBUG_DRY_RUN_RECYCLE", "")
                       .lower() == "true")
            log.warning("[connect] force-recycling pre-existing rphost(s): %s%s",
                        pids_to_kill, " (DRY-RUN)" if dry_run else "")
            # §12.3 Level 3 — track recycle invocation
            _client._force_recycle_invoked = True
            kill_result = force_recycle_rphost_processes(pids_to_kill, dry_run=dry_run)
            _client._recycle_method_used = kill_result.get("method")
            # Дать ragent ~3с на spawn fresh rphost + ping_loop'у поймать event
            # (DBGUIExtCmdInfoStarted → handler → attachDebugTarget).
            await asyncio.sleep(3.0)
            recycle_info = {
                "_tag": "force_recycle_result",
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

        # Solution B: preflight warning when есть pre-existing rphost'ы и
        # пользователь НЕ запросил force-recycle — surface gap явно вместо
        # silent BP-no-fire (root cause § 10).
        if pre_existing_rphosts and not force_recycle_rphost:
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
                    "(тонкий клиент с /Debug /DebuggerURL — validated)",
                    "Solution A: retry с force_recycle_rphost=True (kills pre-"
                    "existing, ragent spawn'ит fresh worker с активным filter; "
                    "РИСК: разрыв активных пользовательских сессий)",
                    "Manual: Console кластера → «Выключить» процесс (graceful "
                    "drain активных сессий другому worker'у) → retry connect",
                ],
                "roadmap_ref": (
                    "docs/roadmap/260508_ROADMAP_BSL_DEBUG_WRAPPER_POST_BP_HANDSHAKE.md"
                    " §10 + §11"
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
    return (f"Wrapper file modified {age_sec}s after MCP start — "
            f"running stale code. Run /mcp reconnect to pick up changes.")


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
            "ui_plus_retries": (curr.get("ui_plus_retries", 0)
                                - prev.get("ui_plus_retries", 0)),
            "stop_events_count": (len(curr.get("stop_events", []))
                                  - len(prev.get("stop_events", []))),
        },
    }
    if diff["deltas"]["bp_fire_count"] < 0:
        diff["regression_indicators"].append(
            f"BP fire_count regressed: -{abs(diff['deltas']['bp_fire_count'])}")
    if diff["deltas"]["eval_failures"] > 0:
        diff["regression_indicators"].append(
            f"eval failures increased: +{diff['deltas']['eval_failures']}")
    if diff["deltas"]["ui_plus_retries"] > 0:
        diff["regression_indicators"].append(
            f"UI+ retries increased: +{diff['deltas']['ui_plus_retries']}")
    diff["verdict"] = ("REGRESSION" if diff["regression_indicators"]
                        else "NO_REGRESSION")
    return diff


@mcp.tool()
async def debug_session_diff(prev_session_id: str,
                              curr_session_id: Optional[str] = None) -> str:
    """Roadmap §12.7 Level 3 extension — cross-session diff для regression detection.

    Compares 2 session summaries. Returns deltas + regression_indicators list.

    Args:
        prev_session_id: baseline session UUID
        curr_session_id: comparison session UUID (default: current active session)
    """
    prev = _load_session_summary(prev_session_id)
    if not prev:
        return json.dumps({"status": "error",
                            "error": f"prev_session_id {prev_session_id} not found"})
    if curr_session_id:
        curr = _load_session_summary(curr_session_id)
        if not curr:
            return json.dumps({"status": "error",
                                "error": f"curr_session_id {curr_session_id} not found"})
    else:
        # Build summary from current _client
        global _client
        if _client is None:
            return json.dumps({"status": "error",
                                "error": "no current session and no curr_session_id"})
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
        format: "json" (structured) | "markdown" (human-readable PR transcript)

    Если нет активной session (debug_connect не вызывался) — возвращает
    {"status": "no_session"}.
    """
    global _client
    if _client is None:
        return json.dumps({"status": "no_session"})

    cache_lines_total = sum(len(e.get("lines", []))
                            for e in _client._set_breakpoints_cache)
    summary = {
        "session_id": _client.session_id,
        "started_at": _client._session_started_at,
        "infobase_alias": _client.infobase_alias,
        "attached": _client._attached,
        "breakpoints": {
            "set_count": cache_lines_total,
            "fire_count": _client._bp_fire_count,
            "by_location": dict(_client._bp_by_location),
            "fire_rate": (_client._bp_fire_count / cache_lines_total
                          if cache_lines_total else None),
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
    return json.dumps(summary, ensure_ascii=False, indent=2)


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
    svc_env = (checks.get("env_vars", {}).get("_extras", {})
               .get("BSL_DEBUG_ALLOW_SERVICE_RESTART"))
    if sddl_pass and svc_env:
        auto_prepare.append("restart-ragent")

    actions_executed: list = []
    if mode == "prepare":
        if not actions:
            return json.dumps({"status": "error",
                               "error": "mode=prepare requires non-empty actions list"})
        whitelist = {"kill-stale-rphosts", "restart-ragent"}
        for action in actions:
            if action not in whitelist:
                actions_executed.append({"action": action,
                                          "result": "rejected: not in whitelist"})
                continue
            if action == "kill-stale-rphosts":
                rphosts = detect_pre_existing_rphosts()
                pids = [r["pid"] for r in rphosts]
                if pids:
                    res = force_recycle_rphost_processes(pids)
                    actions_executed.append({"action": action, "result": res})
                else:
                    actions_executed.append({"action": action,
                                              "result": "no rphosts to kill"})
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
    return json.dumps({
        "targets": targets,
        "count": len(targets),
        "stopped_target": stopped,
    }, ensure_ascii=False, indent=2)


@mcp.tool()
async def debug_ping() -> str:
    """Ping debug server for pending events (breakpoint hit, target started/quit)."""
    client = _get_client()
    events = await client.ping()
    return json.dumps({"events": events, "count": len(events)},
                      ensure_ascii=False, indent=2)


@mcp.tool()
async def debug_stack_trace(target_id: str = "") -> str:
    """Get call stack of a stopped debug target.

    Args:
        target_id: UUID from debug_targets. If empty, auto-finds stopped target.
    """
    client = _get_client()
    if not target_id:
        targets = await client.get_targets()
        target_id = _find_stopped_target(targets) or ""
        if not target_id:
            return json.dumps({"error": "No stopped targets", "targets": targets},
                              ensure_ascii=False, indent=2)
    stack = await client.get_call_stack(target_id)
    return json.dumps({"target_id": target_id, "stack": stack, "depth": len(stack)},
                      ensure_ascii=False, indent=2)


@mcp.tool()
async def debug_variables(target_id: str = "", stack_level: int = 0,
                           expressions: Optional[list[str]] = None) -> str:
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
    client = _get_client()
    if not target_id:
        target_id = client.last_stopped_target_id or ""
        if not target_id:
            targets = await client.get_targets()
            target_id = _find_stopped_target(targets) or ""
        if not target_id:
            return json.dumps({"error": "No stopped targets"})
    if expressions:
        variables = await client.eval_local_variables(
            target_uuid=target_id, stack_level=stack_level,
            expressions=expressions,
        )
        mode = "explicit"
    else:
        variables = await client.eval_locals_auto(
            target_uuid=target_id, stack_level=stack_level,
        )
        mode = "auto"
    return json.dumps({"target_id": target_id, "variables": variables,
                       "count": len(variables), "stack_level": stack_level,
                       "mode": mode},
                      ensure_ascii=False, indent=2)


@mcp.tool()
async def debug_evaluate(expression: str, target_id: str = "",
                         stack_level: int = 0) -> str:
    """Evaluate a BSL expression in context of a stopped target.

    Args:
        expression: BSL expression (e.g. "Контрагент.ИНН", "ТекущаяДата()")
        target_id: UUID from debug_targets. If empty, использует ping
            cached state (P1.3) или fallback на get_targets pull.
        stack_level: 0 = current frame.
    """
    client = _get_client()
    if not target_id:
        target_id = client.last_stopped_target_id or ""
        if not target_id:
            targets = await client.get_targets()
            target_id = _find_stopped_target(targets) or ""
        if not target_id:
            return json.dumps({"error": "No stopped targets"})
    result = await client.eval_expression(
        expression=expression, target_uuid=target_id, stack_level=stack_level,
    )
    return json.dumps({"expression": expression, "result": result},
                      ensure_ascii=False, indent=2)


@mcp.tool()
async def debug_set_breakpoint(
    object_id: str,
    line: int,
    module_type: str = "CommonModule",
    property_id: str = "",
) -> str:
    """Set a breakpoint in a BSL module.

    Args:
        object_id: UUID of metadata object (CommonModule UUID, Document UUID, ...)
            from edt-mcp get_metadata_details.
        property_id: Optional explicit propertyID UUID. Leave empty to auto-resolve
            from module_type via MODULE_PROPERTY_IDS magic UUIDs.
        line: Line number.
        module_type: BSL module kind: CommonModule | ManagerModule | ObjectModule |
            RecordSetModule | FormModule | CommandModule. When this matches a known
            kind, propertyID auto-resolves and XML type is set to "ConfigModule"
            (platform disambiguates by propertyID, not type literal).
    """
    client = _get_client()
    if not client._attached:
        return json.dumps({"error": "Not connected. Call debug_connect first."})
    # Auto-resolve propertyID from MODULE_PROPERTY_IDS when zero/empty (RDBG silently
    # ignores BPs with zero propertyID — see cache/dbgs-rdbg-debug-server.md §11).
    # Re-attach moved out: debug_connect handles initial attach; повторный attach
    # перед каждым set_breakpoint ломает established BP-delivery state в dbgs.exe.
    xml_module_type = module_type
    if not property_id or property_id == ZERO_UUID:
        kind_uuid = MODULE_PROPERTY_IDS.get(module_type, "")
        if kind_uuid:
            property_id = kind_uuid
            xml_module_type = "ConfigModule"
    result = await client.set_breakpoints(
        module_type=xml_module_type,
        object_id=object_id,
        property_id=property_id,
        lines=[line],
    )
    return json.dumps({
        "status": "breakpoint_set",
        "object_id": object_id,
        "property_id": property_id,
        "line": line,
        "module_type": module_type,
        "response": result,
    }, ensure_ascii=False, indent=2)


@mcp.tool()
async def debug_step(action: str = "Continue", target_id: str = "") -> str:
    """Control execution: Continue, Step (over), StepIn, StepOut.

    Args:
        action: Continue | Step | StepIn | StepOut
        target_id: UUID from debug_targets. If empty, использует ping
            cached state (P1.3) или fallback на get_targets pull.
    """
    client = _get_client()
    if not target_id:
        target_id = client.last_stopped_target_id or ""
        if not target_id:
            targets = await client.get_targets()
            target_id = _find_stopped_target(targets) or ""
        if not target_id:
            return json.dumps({"error": "No stopped targets"})
    result = await client.step(action=action, target_uuid=target_id)
    return json.dumps({"action": action, "target_id": target_id, "result": result},
                      ensure_ascii=False, indent=2)


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
    return json.dumps({"breakpoints": bps, "count": len(bps)},
                      ensure_ascii=False, indent=2)


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
        return json.dumps({
            "status": "ok",
            "action": "attach" if attach else "detach",
            "target_ids": target_ids,
            "count": len(target_ids),
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, ensure_ascii=False)


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
        return json.dumps({
            "status": "ok",
            "action": "break_on_next_statement_armed",
            "next_step": (
                "Trigger any BSL execution; then debug_targets to see "
                "captured target; then set precise BP + debug_step Continue."
            ),
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, ensure_ascii=False)


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
    return json.dumps({"target_id": target_id or None, "state": state},
                      ensure_ascii=False, indent=2)


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

    p_summary = sub.add_parser("session-summary",
                                help="Print session summary by session_id или current")
    p_summary.add_argument("--format", default="json",
                            choices=("json", "markdown"))

    p_diff = sub.add_parser("session-diff",
                              help="Diff 2 persisted sessions для regression detection")
    p_diff.add_argument("--prev", required=True, help="prev session UUID")
    p_diff.add_argument("--curr", default=None, help="curr session UUID (default: current)")

    args = parser.parse_args()

    if args.cmd == "health-check":
        result = asyncio.run(debug_health_check())
    elif args.cmd == "session-summary":
        result = asyncio.run(debug_session_summary(format=args.format))
    elif args.cmd == "session-diff":
        result = asyncio.run(
            debug_session_diff(prev_session_id=args.prev,
                                curr_session_id=args.curr)
        )
    else:
        parser.print_help()
        return 2
    print(result)
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("health-check", "session-summary",
                                              "session-diff"):
        sys.exit(_cli_main())
    mcp.run()
