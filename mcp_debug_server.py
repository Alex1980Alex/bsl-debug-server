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
import sys
import uuid
import xml.etree.ElementTree as ET
from typing import Optional

import httpx
from mcp.server.fastmcp import FastMCP

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

    async def _post(self, command: str, body: str,
                    include_dbgui_url: bool = False) -> ET.Element:
        """POST to RDBG endpoint. Only ping uses dbgui in URL."""
        url = f"{self.debug_url}/e1crdbg/rdbg?cmd={command}"
        if include_dbgui_url:
            url += f"&dbgui={self.session_id}"
        log.debug("POST %s", url)
        resp = await self._http.post(url, content=body)
        if resp.status_code >= 400:
            err_body = (resp.text or "")[:2000]
            log.error("RDBG %s -> HTTP %s body=%s", command, resp.status_code, err_body)
            raise httpx.HTTPStatusError(
                f"RDBG {command} {resp.status_code}: {err_body}",
                request=resp.request, response=resp,
            )
        text = resp.text.lstrip("\ufeff")
        if not text:
            return ET.Element("empty")
        return ET.fromstring(text)

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
        body = _build_request(
            self._base_fields(),
            _rdbg("options", _rdbg("foregroundAbility", "false")),
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

    async def _handle_command(self, cmd: dict) -> None:
        """Process single DBGUIExtCmdInfo* event from ping response.

        Roadmap §13.12 spec — see cache/dbgs-rdbg-debug-server.md.
        XML wire literal `cmdId` (lowercase) is matched, NOT enum names.
        """
        cmd_type = cmd.get("cmdId") or ""
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

        elif cmd_type in ("ForegroundHelperSet", "ForegroundHelperRequest",
                           "ForegroundHelperProcess", "measureResultProcessing",
                           "errorViewInfo", "rteOnBPConditionProcessing",
                           "exprEvaluated", "valueModified", "unknown", ""):
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

    async def init_settings(self, target_types: list[str] | None = None) -> bool:
        """Initialize debug settings with autoAttach configuration."""
        types = target_types or ["Server", "ManagedClient"]
        auto_attach = "".join(_auto("targetType", t) for t in types)
        body = _build_request(
            self._base_fields(),
            _rdbg("data",
                   _rdbg("breakOnNextLine", "false")
                   + _rdbg("autoAttachSettings", auto_attach)),
        )
        await self._post("initSettings", body)
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

    # -- Observation API ---------------------------------------------------

    async def get_target_state(self, target_uuid: Optional[str] = None) -> dict:
        """Get state of a single debug target (RDBGGetDbgTargetStateRequest).

        Roadmap §4.4 P2.4 diagnostic. yukon39 не передаёт `id` в этом запросе —
        Java-ской `getTargetState()` шлёт без targetID и сервер возвращает
        состояние UI session (а не конкретного target). Наш wrapper делает
        то же поведение если target_uuid не задан, иначе ищет в результатах
        get_targets() (RDBG single-state endpoint имеет недокументированный
        contract — safe path: фильтр по нашему `get_targets`).
        """
        if target_uuid is None:
            body = _build_request(self._base_fields())
            root = await self._post("getDbgTargetState", body)
            result: dict = {"_tag": "session_state"}
            for child in root:
                tag = _strip_ns(child.tag)
                if child.text and child.text.strip():
                    result[tag] = child.text.strip()
            return result
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
                                    stack_level: int = 0) -> list[dict]:
        """Evaluate local variables at a breakpoint (list all variables).

        Roadmap §13 P1.2: idempotent re-attach перед запросом для защиты
        от race window (ping event-loop не успел обработать stop event).
        """
        target_uuid = self._resolve_target_uuid(target_uuid)
        if not target_uuid:
            raise ValueError("eval_local_variables: no target_uuid and no last_stopped")
        await self._ensure_target_attached(target_uuid)
        body = _build_request(
            self._base_fields(),
            _rdbg("calcWaitingTime", "3"),
            _rdbg("targetID", _target_id_light(target_uuid)),
            _rdbg("expr", _calc("stackLevel", str(stack_level))),
        )
        root = await self._post("evalLocalVariables", body)
        return _parse_response(root)

    async def eval_expression(self, expression: str,
                               target_uuid: Optional[str] = None,
                               stack_level: int = 0,
                               view_interface: Optional[str] = None,
                               max_text_size: int = 4096) -> list[dict]:
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
        expr_result_id = str(uuid.uuid4())
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
        root = await self._post("evalExpr", body)
        return _parse_response(root)

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
        module_id_xml = _base("type", module_type)
        module_id_xml += _base("objectID", object_id)
        module_id_xml += _base("propertyID", property_id)
        if url:
            module_id_xml += _base("url", url)
        if extension_name:
            module_id_xml += _base("extensionName", extension_name)
        if ext_id:
            module_id_xml += _base("extId", str(ext_id))
        if version:
            module_id_xml += _base("version", version)
        bp_infos = "".join(
            _bp("bpInfo",
                _bp("line", str(line))
                + _bp("isActive", "true")
                + _bp("temp", "false"))
            for line in lines
        )
        workspace_xml = _rdbg("bpWorkspace",
            _bp("moduleBPInfo",
                _bp("id", module_id_xml)
                + bp_infos))
        body = _build_request(self._base_fields(), workspace_xml)
        root = await self._post("setBreakpoints", body)
        # P2.4: cache successful BP-set for client-side debug_get_breakpoints
        self._set_breakpoints_cache.append({
            "module_type": module_type,
            "object_id": object_id,
            "property_id": property_id,
            "lines": list(lines),
            "ext_id": ext_id,
            "url": url,
            "extension_name": extension_name,
            "version": version,
        })
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
# MCP Server
# ---------------------------------------------------------------------------
mcp = FastMCP("1c-debug")


@mcp.tool()
async def debug_connect(debug_url: str = "http://localhost:1550",
                        infobase_alias: str = "TestDB") -> str:
    """Connect to 1C debug agent and attach as debug client.

    IMPORTANT: Only ONE debug UI can be active per infobase.
    If EDT is debugging, you'll get 'ibInDebug' (read-only).
    Stop EDT debugging first for full access ('registered').

    Args:
        debug_url: URL of 1C debug agent (default: http://localhost:1550)
        infobase_alias: Infobase name in 1C cluster
    """
    global _client
    if _client and _client._attached:
        await _client.close()

    _client = RDBGClient(debug_url, infobase_alias)
    try:
        version = await _client.get_api_version()
        existing_id = await _client.get_debug_id()
        attach_result = await _client.attach()
        await _client.init_settings()

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
async def debug_variables(target_id: str = "", stack_level: int = 0) -> str:
    """Read local variables at current breakpoint.

    Args:
        target_id: UUID from debug_targets. If empty, использует cached
            _last_stopped_target_id (roadmap §13 P1.3) или fallback на
            get_targets pull.
        stack_level: 0 = current frame, 1 = caller, etc.
    """
    client = _get_client()
    if not target_id:
        # P1.3: prefer ping event-loop cached state vs slower pull
        target_id = client.last_stopped_target_id or ""
        if not target_id:
            targets = await client.get_targets()
            target_id = _find_stopped_target(targets) or ""
        if not target_id:
            return json.dumps({"error": "No stopped targets"})
    variables = await client.eval_local_variables(
        target_uuid=target_id, stack_level=stack_level,
    )
    return json.dumps({"target_id": target_id, "variables": variables,
                       "count": len(variables), "stack_level": stack_level},
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
async def debug_target_state(target_id: str = "") -> str:
    """Get state of a single debug target (or current Debug UI session).

    Roadmap §4.4 P2.4 diagnostic. Если target_id пуст — возвращает state
    самой Debug UI session (yukon39 getTargetState без targetID); иначе
    фильтрует результат get_targets() по target_id.

    Args:
        target_id: UUID цели или пусто для UI session state.
    """
    client = _get_client()
    if not client._attached:
        return json.dumps({"error": "Not connected. Call debug_connect first."})
    state = await client.get_target_state(target_uuid=target_id or None)
    return json.dumps({"target_id": target_id or None, "state": state},
                      ensure_ascii=False, indent=2)


if __name__ == "__main__":
    mcp.run()
