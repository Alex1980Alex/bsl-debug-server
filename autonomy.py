"""A0/A1 roadmap 260708 §7: agent-centric composite debug primitives.

`build_frame_bundle` collapses stack_trace → variables → N×evaluate into one
rich "frame bundle" (ADI / InspectCoder pattern): current frame +
resolved_source + auto-discovered locals + source context. Reused by
`debug_inspect_frame` (A0) and `debug_autotrace` (A1).

Standalone like logpoints/coverage/system_stops — imports uuid_index directly,
receives `client`, never imports mcp_debug_server (avoids circular import).
"""

from __future__ import annotations

import logging
from pathlib import Path

import uuid_index

log = logging.getLogger("1c-debug-mcp.autonomy")


def read_source_context(
    object_id: str,
    property_id: str,
    line_no: int,
    radius: int = 3,
) -> dict | None:
    """Read source lines [line-radius, line+radius] with the current line marked.

    Returns {file_path, start, end, lines:[{n, text, current}]} or None if the
    source path can't be resolved / read. Never raises.
    """
    try:
        path = uuid_index.resolve_uuid(object_id, property_id)
    except Exception as e:  # resolver is best-effort
        log.warning("read_source_context resolve failed: %s", e)
        path = None
    if path is None or not Path(path).exists():
        return None
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception as e:
        log.warning("read_source_context read failed for %s: %s", path, e)
        return None
    lo = max(1, line_no - radius)
    hi = min(len(text), line_no + radius)
    lines = [{"n": n, "text": text[n - 1], "current": n == line_no} for n in range(lo, hi + 1)]
    return {"file_path": str(path), "start": lo, "end": hi, "lines": lines}


async def build_frame_bundle(
    client,
    target_id: str,
    stack_level: int = 0,
    context_radius: int = 3,
) -> dict:
    """Compose a rich frame bundle for one stopped target.

    Args:
        client: RDBGClient with an already-resolved/attached target.
        target_id: concrete target UUID (caller resolves via
            _resolve_stopped_target).
        stack_level: 0 = innermost/current frame, 1 = caller, ...
        context_radius: source lines above/below the current line.

    Returns:
        {target_id, stack_level, depth, frame, resolved_source,
         source_context, locals, locals_mode}. On out-of-range stack_level
        returns {target_id, error, depth}. Never raises for "no source" /
        "no locals" — degrades with `locals_mode` / null so the agent still
        gets the frame + stack.
    """
    # Prefer cached stack (populated by ping callStackFormed); pull on miss and
    # backfill the cache so eval_locals_auto (which reads the cache) can work.
    stack = client._last_stack_by_target.get(target_id)
    if not stack:
        stack = await client.get_call_stack(target_id)
        if stack:
            client._last_stack_by_target[target_id] = stack
    stack = stack or []
    depth = len(stack)
    if stack_level < 0 or stack_level >= depth:
        return {
            "target_id": target_id,
            "error": f"stack_level {stack_level} out of range (depth={depth})",
            "depth": depth,
        }

    frame = stack[stack_level]
    frame = dict(frame) if isinstance(frame, dict) else {"raw": frame}
    mod = frame.get("moduleID") if isinstance(frame.get("moduleID"), dict) else {}
    object_id = mod.get("objectID", "")
    property_id = mod.get("propertyID", "")

    resolved = uuid_index.get_source_info(object_id, property_id) or None
    if resolved:
        frame["resolved_source"] = resolved

    try:
        line_no = int(frame.get("lineNo", 0))
    except (TypeError, ValueError):
        line_no = 0

    source_context = None
    if object_id and property_id and line_no > 0:
        source_context = read_source_context(
            object_id,
            property_id,
            line_no,
            context_radius,
        )

    locals_list: list = []
    locals_mode = "auto"
    try:
        locals_list = await client.eval_locals_auto(
            target_uuid=target_id,
            stack_level=stack_level,
        )
    except Exception as e:
        log.warning("build_frame_bundle locals failed: %s", e)
        locals_mode = "error"
        locals_list = []
    if not locals_list and locals_mode == "auto":
        # No source access or no names extracted — frame + context still useful.
        locals_mode = "unavailable"

    return {
        "target_id": target_id,
        "stack_level": stack_level,
        "depth": depth,
        "frame": frame,
        "resolved_source": resolved,
        "source_context": source_context,
        "locals": locals_list,
        "locals_mode": locals_mode,
    }
