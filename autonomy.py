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
import json
import logging
import re
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
        # M-3 (audit 260710): human presentation FIRST — the verdict compares
        # against `expected` written the way the platform presents a value (e.g.
        # Булево → «Истина», not the typed `valueBoolean="true"`). Legacy
        # presentation-ish keys, then base64 `pres`; typed `value*` keys only as a
        # fallback when no presentation is available.
        for key in ("presentation", "value", "_value", "text", "resultValue"):
            if key in item and not isinstance(item[key], (dict, list)):
                return str(item[key]).strip()
        # Review 260710: only use `pres` when NON-EMPTY. Live RDBG sometimes carries
        # an empty `pres` alongside a real typed value (logpoints._scalar guards the
        # same way); an empty pres decoding to "" used to shadow valueDecimal="0" →
        # a false definitive FAIL in the verdict. Empty → fall through to typed.
        if item.get("pres") and not isinstance(item["pres"], (dict, list)):
            decoded = _decode_pres_b64(item["pres"])
            if decoded:
                return decoded
        for key in ("valueDecimal", "valueStr", "valueBoolean"):
            if key in item and not isinstance(item[key], (dict, list)):
                return str(item[key]).strip()
        # descend into a nested value container
        nxt = item.get("resultValueInfo") or item.get("calcResult") or item.get("result")
        if nxt is None or nxt is item:
            break
        item = nxt
        seen += 1
    return str(result).strip()


def _eval_inconclusive(res) -> bool:
    """M-3 (audit 260710): True if an eval result couldn't produce a value —
    empty `[]` (evalExpr timed out before the async value arrived) or an error/
    pending `evalResultState`. Such a check is INCONCLUSIVE, not FAIL: eval gave no
    value, so a mismatch is not evidence of a bug (an agent must not «prove» a bug
    that isn't there)."""
    if not res:
        return True
    item = res[0] if isinstance(res, list) else res
    if isinstance(item, dict):
        state = str(item.get("evalResultState", "")).lower()
        if state in ("error", "timeout", "pending", "notevaluated", "notcalculated"):
            return True
    return False


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
    for expr, expected in expect.items():
        expected_s = str(expected).strip()
        err = False
        try:
            res = await client.eval_expression(
                expression=expr,
                target_uuid=target_id,
                stack_level=stack_level,
            )
            if _eval_inconclusive(res):
                actual = _extract_eval_value(res)
                ok = False
                err = True
            else:
                actual = _extract_eval_value(res)
                ok = actual == expected_s
        except Exception as e:
            actual = f"<eval-error: {e}>"
            ok = False
            err = True
        checked.append(
            {"expr": expr, "expected": expected_s, "actual": actual, "ok": ok, "error": err}
        )
    # M-3 (audit 260710): a DEFINITIVE mismatch (eval produced a value ≠ expected)
    # → FAIL, and it takes precedence over an INCONCLUSIVE sibling so a real bug is
    # never masked by an unrelated eval-error. Only when there is no definitive
    # mismatch but some check couldn't be evaluated → INCONCLUSIVE. All good → PASS.
    definitive_fail = any((not c["ok"]) and (not c["error"]) for c in checked)
    has_error = any(c["error"] for c in checked)
    if definitive_fail:
        status = "FAIL"
    elif has_error:
        status = "INCONCLUSIVE"
    else:
        status = "PASS"
    reason = "; ".join(
        f"{c['expr']}={c['actual']}"
        + (" (eval-error)" if c["error"] else ("" if c["ok"] else f" ≠ {c['expected']}"))
        for c in checked
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


def extract_exception_symptom(exc) -> dict:
    """Best-effort {code, message} from an RDBG exception dict (shape varies).

    Live shape (rteProcessing): `{code, info}`; exception_bps also probes
    `messageText/message/text/description`. Walk a superset, never raise.
    """
    if not isinstance(exc, dict):
        return {"code": "", "message": ""}
    code = ""
    for k in ("code", "_code", "errorCode"):
        v = exc.get(k)
        if v not in (None, "", {}, []):
            code = str(v).strip()
            break
    message = ""
    for k in ("messageText", "message", "info", "text", "description", "descr"):
        v = exc.get(k)
        if isinstance(v, str) and v:
            message = v.strip()
            break
    return {"code": code, "message": message}


async def build_diagnosis_record(
    client,
    target_id: str,
    max_frames: int = 3,
    context_radius: int = 2,
) -> dict:
    """A2 (roadmap 260708 §7.6 / SWE-Doctor): structured diagnosis-record from an
    exception stop — fault location, runtime symptom, propagation path, observed
    values.

    Args:
        client: RDBGClient with an exception-stopped target (reason="exception").
        target_id: concrete target UUID.
        max_frames: how many innermost frames to inspect WITH locals (bounded —
            deep-frame eval is costly and the ephemeral-JOB halt window is 1-2s).
        context_radius: source lines above/below per inspected frame.

    Returns {fault_location, runtime_symptom, propagation_path, frames_inspected,
    frames_total, frames_bounded}. The full stack is always in
    `propagation_path`; `frames_bounded`/`frames_total` surface any truncation
    (no silent cap — roadmap §3 op-note 4). Never raises for "no source"/"no
    locals" — degrades via build_frame_bundle's own graceful modes.
    """
    # Prefer cached stack (populated by rteProcessing/callStackFormed); pull on miss.
    stack = client._last_stack_by_target.get(target_id)
    if not stack:
        try:
            stack = await client.get_call_stack(target_id)
        except Exception as e:
            log.warning("build_diagnosis_record stack pull failed: %s", e)
            stack = []
        if stack:
            client._last_stack_by_target[target_id] = stack
    stack = stack or []
    depth = len(stack)

    exc = getattr(client, "_last_exception_by_target", {}).get(target_id) or {}
    symptom = extract_exception_symptom(exc)

    # Propagation path — lightweight per-frame (RDBG callStack = OUTERMOST-first,
    # so index 0 = outermost caller, last = fault frame; cheap resolve, no eval).
    propagation_path: list = []
    for i, fr in enumerate(stack):
        frd = fr if isinstance(fr, dict) else {}
        mod = frd.get("moduleID") if isinstance(frd.get("moduleID"), dict) else {}
        info = uuid_index.get_source_info(mod.get("objectID", ""), mod.get("propertyID", "")) or {}
        propagation_path.append(
            {
                "index": i,
                "fqn": info.get("fqn"),
                "file_path": info.get("file_path"),
                "line": frd.get("lineNo"),
            }
        )

    # Observed values — top-N innermost frames (stack_level 0..n-1) WITH locals +
    # source context. stack_level indexing is innermost-first (Ф-2), matching
    # build_frame_bundle, so level 0 = the fault frame.
    n = max(0, min(max_frames, depth))
    frames_inspected: list = []
    for lvl in range(n):
        frames_inspected.append(
            await build_frame_bundle(
                client, target_id, stack_level=lvl, context_radius=context_radius
            )
        )

    # Fault location = innermost frame (stack_level 0).
    fault_location = None
    if frames_inspected:
        fb = frames_inspected[0]
        rs = fb.get("resolved_source") or {}
        frame = fb.get("frame") or {}
        fault_location = {
            "fqn": rs.get("fqn"),
            "file_path": rs.get("file_path"),
            "line": frame.get("lineNo"),
        }
    elif stack:
        # LOW (audit 260710): max_frames=0 → no inspected frames, but the fault
        # frame is still computable from the raw stack (innermost = last, Ф-2).
        fr = stack[-1] if isinstance(stack[-1], dict) else {}
        mod = fr.get("moduleID") if isinstance(fr.get("moduleID"), dict) else {}
        info = uuid_index.get_source_info(mod.get("objectID", ""), mod.get("propertyID", "")) or {}
        fault_location = {
            "fqn": info.get("fqn"),
            "file_path": info.get("file_path"),
            "line": fr.get("lineNo"),
        }

    return {
        "fault_location": fault_location,
        "runtime_symptom": symptom,
        "propagation_path": propagation_path,
        "frames_inspected": frames_inspected,
        "frames_total": depth,
        "frames_bounded": n < depth,
    }


def build_seed_diagnosis(symptom: dict, stack: list) -> dict:
    """H-5 (audit 260710): degraded diagnosis-record from a cheap eager seed
    (symptom + stack captured in _handle_command(rteProcessing), NO eval).

    Used by debug_root_cause collect when the ephemeral JOB force-resumed/quit
    before collect could inspect the live frame (targetQuit popped the exception).
    Same shape as build_diagnosis_record but `frames_inspected=[]` (no live locals)
    and `window_closed=True` so the caller/agent knows locals are unavailable.
    """
    stack = stack or []
    depth = len(stack)
    propagation_path: list = []
    for i, fr in enumerate(stack):
        frd = fr if isinstance(fr, dict) else {}
        mod = frd.get("moduleID") if isinstance(frd.get("moduleID"), dict) else {}
        info = uuid_index.get_source_info(mod.get("objectID", ""), mod.get("propertyID", "")) or {}
        propagation_path.append(
            {
                "index": i,
                "fqn": info.get("fqn"),
                "file_path": info.get("file_path"),
                "line": frd.get("lineNo"),
            }
        )
    fault_location = None
    if stack:
        # Fault frame = innermost = LAST element (RDBG callStack outermost-first, Ф-2).
        fr = stack[-1] if isinstance(stack[-1], dict) else {}
        mod = fr.get("moduleID") if isinstance(fr.get("moduleID"), dict) else {}
        info = uuid_index.get_source_info(mod.get("objectID", ""), mod.get("propertyID", "")) or {}
        fault_location = {
            "fqn": info.get("fqn"),
            "file_path": info.get("file_path"),
            "line": fr.get("lineNo"),
        }
    return {
        "fault_location": fault_location,
        "runtime_symptom": symptom or {"code": "", "message": ""},
        "propagation_path": propagation_path,
        "frames_inspected": [],
        "frames_total": depth,
        "frames_bounded": depth > 0,
        "window_closed": True,
    }


# ---------------------------------------------------------------------------
# A3 debug_trace_variable — timeline over auto-logpoints (roadmap 260708 §7.6)
# ---------------------------------------------------------------------------

# BSL identifier: Cyrillic/Latin letter or underscore, then word chars (incl. Cyrillic).
_BSL_IDENT_RE = re.compile(r"[A-Za-z_А-яЁё][\wА-яЁё]*")

# Keywords / literals to exclude from "upstream" RHS identifiers (ru + en).
_BSL_KEYWORDS = frozenset(
    w.lower()
    for w in (
        "Если", "Тогда", "Иначе", "ИначеЕсли", "КонецЕсли", "Для", "Каждого", "Из",
        "По", "Цикл", "КонецЦикла", "Пока", "Возврат", "Продолжить", "Прервать",
        "И", "ИЛИ", "НЕ", "Новый", "Истина", "Ложь", "Неопределено", "NULL",
        "Попытка", "Исключение", "КонецПопытки", "ВызватьИсключение", "Перем",
        "Функция", "Процедура", "КонецФункции", "КонецПроцедуры", "Экспорт",
        "If", "Then", "Else", "ElsIf", "EndIf", "For", "Each", "In", "To", "Do",
        "EndDo", "While", "Return", "Continue", "Break", "And", "Or", "Not", "New",
        "True", "False", "Undefined", "Try", "Except", "EndTry", "Raise", "Var",
    )
)


def find_method_range(source_lines: list, method_name: str):
    """1-based inclusive [start, end] line range of `Процедура/Функция method_name`.

    Returns (start, end) or None if not found. `end` is the matching
    `КонецПроцедуры/КонецФункции` (or last line if unterminated).
    """
    if not method_name:
        return None
    esc = re.escape(method_name)
    head = re.compile(rf"^\s*(?:Процедура|Функция|Procedure|Function)\s+{esc}\s*\(", re.IGNORECASE)
    tail = re.compile(r"^\s*(?:КонецПроцедуры|КонецФункции|EndProcedure|EndFunction)\b", re.IGNORECASE)
    start = None
    for i, ln in enumerate(source_lines, start=1):
        if start is None:
            if head.search(ln):
                start = i
        elif tail.search(ln):
            return (start, i)
    return (start, len(source_lines)) if start is not None else None


def _strip_bsl_strings(s: str) -> str:
    """Blank out BSL string literals so their contents aren't parsed as code.

    LENGTH-PRESERVING: each literal's inner chars → spaces, quotes kept. This is
    critical — callers use `find("//")` on the stripped string but index back into
    the ORIGINAL (find_assignment_lines), so positions must stay aligned. A
    non-length-preserving blank ('""') shifted the cut and truncated the RHS mid-
    string for the common «literal + trailing // comment» case (adversarial review
    260710). BSL doubles an inner quote (`""`), so the non-greedy `"[^"]*"` lands
    on real boundaries. Blanks identifiers inside literals (`"Итого по "`) out of
    upstream and stops a `//` inside a literal (`"http://x"`) from truncating.
    """
    return re.sub(r'"[^"]*"', lambda m: '"' + " " * (len(m.group(0)) - 2) + '"', s or "")


def _extract_upstream(rhs: str, name: str, cap: int = 3) -> list:
    """RHS variable identifiers feeding the assignment (best-effort, ru+en).

    Skips keywords, the traced name itself, function-call heads (ident followed by
    `(`), member-access tails (`Объект.Ident`), type names after `Новый`, and
    identifiers inside string literals. Deduped, capped.
    """
    out: list = []
    lname = name.lower()
    rhs = _strip_bsl_strings(rhs)
    for m in _BSL_IDENT_RE.finditer(rhs or ""):
        ident = m.group(0)
        low = ident.lower()
        if low == lname or low in _BSL_KEYWORDS:
            continue
        before = rhs[: m.start()].rstrip()
        # skip member-access tail (`Объект.Ident` — not a standalone variable)
        if before.endswith("."):
            continue
        # skip a type name right after `Новый`/`New` (`Новый ТаблицаЗначений`)
        prev = before.split()[-1].lower() if before.split() else ""
        if prev in ("новый", "new"):
            continue
        # skip call heads (`Ident(` — a method/function call, not a variable)
        if rhs[m.end():].lstrip().startswith("("):
            continue
        if ident not in out:
            out.append(ident)
        if len(out) >= cap:
            break
    return out


def find_assignment_lines(source_lines: list, name: str, line_range=None, upstream: bool = True) -> list:
    """Lines where `name` is assigned (`name = ...` at statement start).

    Statement-start anchoring skips comparison/other contexts (`Если name = ...`,
    `Возврат name`, `Стр.name = ...`). `line_range`=(start,end) 1-based inclusive
    scopes to a method; None = whole module. BSL `=` is both assign and compare —
    only an assignment starts the statement with the bare identifier.

    Returns [{line, text, rhs, upstream:[...]}] (1-based line numbers).
    """
    if not name:
        return []
    esc = re.escape(name)
    # `^ws NAME ws = (not '=') RHS` — BSL has no '==', the `(?!=)` guards typos.
    assign_re = re.compile(rf"^\s*{esc}\s*=\s*(?!=)(.*)$", re.IGNORECASE)
    lo, hi = (line_range or (1, len(source_lines)))
    out: list = []
    for i in range(max(1, lo), min(len(source_lines), hi) + 1):
        text = source_lines[i - 1]
        m = assign_re.match(text)
        if not m:
            continue
        rhs = m.group(1).strip()
        # strip trailing line comment + semicolon for cleaner upstream parsing.
        # Blank string literals FIRST so a `//` inside a literal ("http://x")
        # doesn't truncate the RHS mid-string (LOW audit 260710).
        rhs_nostr = _strip_bsl_strings(rhs)
        cut = rhs_nostr.find("//")
        rhs_code = (rhs[:cut] if cut != -1 else rhs).rstrip().rstrip(";").strip()
        out.append(
            {
                "line": i,
                "text": text.rstrip(),
                "rhs": rhs_code,
                "upstream": _extract_upstream(rhs_code, name) if upstream else [],
            }
        )
    return out


def build_trace_template(name: str, upstream: list) -> str:
    """Logpoint template capturing `name` (+ upstream vars): `name={name} u={u}`.

    Each `{expr}` is evaluated in the stopped frame by the logpoint machinery.
    """
    parts = [f"{name}={{{name}}}"]
    for u in upstream or []:
        parts.append(f"{u}={{{u}}}")
    return " ".join(parts)


def read_trace_timeline(log_dir, session_id: str, keys: set, skip_lines: int, name: str) -> list:
    """Read the logpoint JSONL and build the value timeline for one trace.

    Filters to entries whose (object_id, property_id, line) ∈ `keys` and skips the
    first `skip_lines` (entries that predate arm). Returns
    [{line, ts, value, values, rendered}] in file order (chronological).
    """
    path = Path(log_dir) / f"{session_id}.jsonl"
    if not path.exists():
        return []
    try:
        raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as e:
        log.warning("read_trace_timeline read failed (%s): %s", path, e)
        return []
    out: list = []
    for raw in raw_lines[skip_lines:]:
        raw = raw.strip()
        if not raw:
            continue
        try:
            e = json.loads(raw)
        except (ValueError, TypeError):
            continue
        k = (e.get("object_id"), e.get("property_id"), e.get("line"))
        if k not in keys:
            continue
        evaluated = e.get("evaluated") if isinstance(e.get("evaluated"), dict) else {}
        out.append(
            {
                "line": e.get("line"),
                "ts": e.get("ts"),
                "value": evaluated.get(name),
                "values": evaluated,
                "rendered": e.get("rendered"),
            }
        )
    return out
