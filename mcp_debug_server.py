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

import json
import logging
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

    async def _post(self, command: str, body: str,
                    include_dbgui_url: bool = False) -> ET.Element:
        """POST to RDBG endpoint. Only ping uses dbgui in URL."""
        url = f"{self.debug_url}/e1crdbg/rdbg?cmd={command}"
        if include_dbgui_url:
            url += f"&dbgui={self.session_id}"
        log.debug("POST %s", url)
        resp = await self._http.post(url, content=body)
        resp.raise_for_status()
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

    async def attach(self) -> dict:
        """Attach as debug UI. Returns 'registered' or 'ibInDebug'."""
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
        return {"result": result, "session_id": self.session_id,
                "fully_registered": self._registered}

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

    async def get_call_stack(self, target_uuid: str) -> list[dict]:
        """Get call stack. Note: uses 'id' field, not 'targetID'."""
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

    async def eval_local_variables(self, target_uuid: str,
                                    stack_level: int = 0) -> list[dict]:
        """Evaluate local variables at a breakpoint (list all variables)."""
        body = _build_request(
            self._base_fields(),
            _rdbg("calcWaitingTime", "3"),
            _rdbg("targetID", _target_id_light(target_uuid)),
            _rdbg("expr", _calc("stackLevel", str(stack_level))),
        )
        root = await self._post("evalLocalVariables", body)
        return _parse_response(root)

    async def eval_expression(self, target_uuid: str, expression: str,
                               stack_level: int = 0) -> list[dict]:
        """Evaluate a specific BSL expression at a breakpoint."""
        expr_result_id = str(uuid.uuid4())
        src_calc_info = (
            _calc("expressionResultID", expr_result_id)
            + _calc("calcItem",
                    _calc("itemType", "expression")
                    + _calc("expression", expression))
        )
        pres_options = _calc("maxTextSize", "1000")
        expr_xml = (
            _calc("stackLevel", str(stack_level))
            + _calc("srcCalcInfo", src_calc_info)
            + _calc("presOptions", pres_options)
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

    async def step(self, target_uuid: str, action: str = "Continue") -> list[dict]:
        """Step execution. Actions: Continue, Step, StepIn, StepOut."""
        body = _build_request(
            self._base_fields(),
            _rdbg("targetID", _target_id_light(target_uuid)),
            _rdbg("action", action),
        )
        root = await self._post("step", body)
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
            version: Config version (usually empty).
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

        # Auto-attach to stopped target if found
        if stopped and _client._registered:
            await _client.attach_debug_targets([stopped])

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
        target_id: UUID from debug_targets. If empty, auto-finds stopped target.
        stack_level: 0 = current frame, 1 = caller, etc.
    """
    client = _get_client()
    if not target_id:
        targets = await client.get_targets()
        target_id = _find_stopped_target(targets) or ""
        if not target_id:
            return json.dumps({"error": "No stopped targets"})
    variables = await client.eval_local_variables(target_id, stack_level)
    return json.dumps({"target_id": target_id, "variables": variables,
                       "count": len(variables), "stack_level": stack_level},
                      ensure_ascii=False, indent=2)


@mcp.tool()
async def debug_evaluate(expression: str, target_id: str = "",
                         stack_level: int = 0) -> str:
    """Evaluate a BSL expression in context of a stopped target.

    Args:
        expression: BSL expression (e.g. "Контрагент.ИНН", "ТекущаяДата()")
        target_id: UUID from debug_targets. If empty, auto-finds stopped target.
        stack_level: 0 = current frame.
    """
    client = _get_client()
    if not target_id:
        targets = await client.get_targets()
        target_id = _find_stopped_target(targets) or ""
        if not target_id:
            return json.dumps({"error": "No stopped targets"})
    result = await client.eval_expression(target_id, expression, stack_level)
    return json.dumps({"expression": expression, "result": result},
                      ensure_ascii=False, indent=2)


@mcp.tool()
async def debug_set_breakpoint(
    object_id: str,
    property_id: str,
    line: int,
    module_type: str = "ExtMDModule",
) -> str:
    """Set a breakpoint in a BSL module.

    Use edt-mcp get_metadata_details to find objectID and propertyID UUIDs.

    Args:
        object_id: UUID of metadata object (DataProcessor, Document, etc.)
        property_id: UUID of the form or module within the object.
        line: Line number to set breakpoint on.
        module_type: BSLModuleType: ExtMDModule (form modules),
                     ConfigModule (common modules), SystemModule (session module).
    """
    client = _get_client()
    if not client._attached:
        return json.dumps({"error": "Not connected. Call debug_connect first."})
    result = await client.set_breakpoints(
        module_type=module_type,
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
        target_id: UUID from debug_targets. If empty, auto-finds stopped target.
    """
    client = _get_client()
    if not target_id:
        targets = await client.get_targets()
        target_id = _find_stopped_target(targets) or ""
        if not target_id:
            return json.dumps({"error": "No stopped targets"})
    result = await client.step(target_id, action)
    return json.dumps({"action": action, "target_id": target_id, "result": result},
                      ensure_ascii=False, indent=2)


if __name__ == "__main__":
    mcp.run()
