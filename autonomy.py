"""A0/A1 roadmap 260708 §7: agent-centric composite debug primitives.

`build_frame_bundle` collapses stack_trace → variables → N×evaluate into one
rich "frame bundle" (ADI / InspectCoder pattern): current frame +
resolved_source + auto-discovered locals + source context. Reused by
`debug_inspect_frame` (A0) and `debug_autotrace` (A1).

Standalone like logpoints/coverage/system_stops — imports uuid_index directly,
receives `client`, never imports mcp_debug_server (avoids circular import).
"""

from __future__ import annotations

import asyncio
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


def build_page_expressions(
    expression: str,
    start: int,
    count: int,
    columns: list | None = None,
) -> list[str]:
    """Build batch index-access BSL expressions for a page of an indexable
    collection (Массив / ТаблицаЗначений / выгрузка РезультатЗапроса).

    C0 roadmap 260708 §7.4 — RDBG has no "expand" call; paging is emulated as a
    batch of `<expr>[i]` reads (+ `.<column>` per row when `columns` given) sent
    in one evalLocalVariables POST. Lazy access to huge collections без обрезки /
    взрыва контекста.

    SECURITY: `expression` и `columns` подставляются в BSL-выражения и
    исполняются в running rphost через evalLocalVariables (как logpoints/eval) —
    не передавай untrusted значения.

    Returns a flat list of expression strings.
    """
    exprs: list[str] = []
    for i in range(start, start + count):
        base = f"{expression}[{i}]"
        if columns:
            exprs.extend(f"{base}.{col}" for col in columns)
        else:
            exprs.append(base)
    return exprs


def _decode_pres_b64(raw: str) -> str | None:
    """Decode RDBG base64 `pres` presentation ('MA==' → '0'). None on failure."""
    try:
        import base64

        cleaned = "".join(str(raw).split())  # multi-line base64 with \n
        return base64.b64decode(cleaned).decode("utf-8", errors="replace").strip()
    except Exception:
        return None


def _extract_eval_value(result) -> str:
    """Best-effort string presentation of an eval_expression result.

    Live-verified shape (RDBG 8.3.27.1936, 2026-07-08):
    `[{evalResultState, expressionResultID, resultValueInfo: {typeCode,
    typeName, valueDecimal|valueStr|valueBoolean, pres: <base64>}}]` — the
    human presentation is base64 in `pres`; typed value in `value*` keys.
    Walk those plus legacy presentation-ish keys, fall back to str().
    Never raises.
    """
    item = result
    if isinstance(item, list):
        item = item[0] if item else None
    seen = 0
    while isinstance(item, dict) and seen < 6:
        for key in (
            "presentation",
            "value",
            "_value",
            "text",
            "resultValue",
            "valueDecimal",
            "valueStr",
            "valueBoolean",
        ):
            if key in item and not isinstance(item[key], (dict, list)):
                return str(item[key]).strip()
        if "pres" in item and not isinstance(item["pres"], (dict, list)):
            decoded = _decode_pres_b64(item["pres"])
            if decoded is not None:
                return decoded
        # descend into a nested value container
        nxt = item.get("resultValueInfo") or item.get("calcResult") or item.get("result")
        if nxt is None or nxt is item:
            break
        item = nxt
        seen += 1
    return str(result).strip()


async def evaluate_expect(client, target_id: str, expect: dict, stack_level: int = 0) -> dict:
    """Verdict engine (A1.4 roadmap 260708 §7.3).

    Evaluates each `expect` expression against the stopped frame (same eval path
    as debug_evaluate — stack_level, default 0) and compares its string
    presentation to the expected value.

    Args:
        expect: {"<BSL expr>": "<expected presentation>", ...}.

    Returns {status, reason, checked:[{expr, expected, actual, ok}]}.
        status: PASS (all match) / FAIL (some mismatch) / INCONCLUSIVE (an
        eval raised). Comparison is trimmed-string equality — the caller sets
        `expected` to match the platform's value presentation.
    """
    checked: list = []
    any_error = False
    all_ok = True
    for expr, expected in expect.items():
        expected_s = str(expected).strip()
        try:
            res = await client.eval_expression(
                expression=expr,
                target_uuid=target_id,
                stack_level=stack_level,
            )
            actual = _extract_eval_value(res)
            ok = actual == expected_s
        except Exception as e:
            actual = f"<eval-error: {e}>"
            ok = False
            any_error = True
        all_ok = all_ok and ok
        checked.append({"expr": expr, "expected": expected_s, "actual": actual, "ok": ok})
    status = "INCONCLUSIVE" if any_error else ("PASS" if all_ok else "FAIL")
    reason = "; ".join(
        f"{c['expr']}={c['actual']}" + ("" if c["ok"] else f" ≠ {c['expected']}") for c in checked
    )
    return {"status": status, "reason": reason, "checked": checked}


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

    # Ф-2 (live-verified 2026-07-08): RDBG callStack array is OUTERMOST-first
    # (BP frame is the LAST element), while evalExpr/evalLocalVariables
    # stackLevel is INNERMOST-first (0 = current frame). Index frames
    # innermost-first so the bundle frame matches what stack_level evaluates in.
    frame = stack[depth - 1 - stack_level]
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
        # Offload the sync resolve+read to a thread (async-first hygiene).
        source_context = await asyncio.to_thread(
            read_source_context,
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
