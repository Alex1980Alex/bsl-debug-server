"""P0.B roadmap 260511: logpoint message rendering + log emission helper."""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
from datetime import datetime
from pathlib import Path

log = logging.getLogger("1c-debug-mcp.logpoints")

# Strong refs to in-flight deferred logpoint tasks — asyncio keeps only a weak
# ref to create_task() results, so without this they can be GC'd mid-run.
_active_tasks: set = set()


_PLACEHOLDER_RE = re.compile(r"(?<!\{)\{([^{}]+)\}(?!\})")


def extract_placeholders(template: str) -> list[str]:
    """Find `{expr}` placeholders, skipping `{{escaped}}` literals."""
    return _PLACEHOLDER_RE.findall(template or "")


def _top_key(stack):
    top = stack[0] if isinstance(stack, list) and stack else None
    if not isinstance(top, dict):
        return None
    mod = top.get("moduleID") if isinstance(top.get("moduleID"), dict) else {}
    try:
        line = int(top.get("lineNo", 0))
    except (TypeError, ValueError):
        return None
    return (mod.get("objectID", ""), mod.get("propertyID", ""), line)


def _b64(s):
    """Decode RDBG base64-UTF8 field; pass through on any failure."""
    try:
        return base64.b64decode(s).decode("utf-8")
    except Exception:
        return s


def _scalar(v):
    """Reduce an eval_expression result to a readable scalar.

    RDBG evalExpr returns `evalExprResBaseData` -> `resultValueInfo`, where the
    value lives in base64-encoded fields (`valueString` / `pres`) or plain typed
    fields (`valueBoolean` / `valueDecimal`). Prefer the cleanest typed value,
    fall back to the base64 presentation, then the raw shape.
    """
    if isinstance(v, list):
        if not v:
            return ""
        v = v[0]
    if not isinstance(v, dict):
        return v
    info = v.get("resultValueInfo")
    if not isinstance(info, dict):
        for k in ("presentation", "value", "valueAsString", "result"):
            if v.get(k) not in (None, ""):
                return v[k]
        return v
    if info.get("valueString") not in (None, ""):
        return _b64(info["valueString"])
    vb = info.get("valueBoolean")
    if vb not in (None, ""):
        return {"true": "Истина", "false": "Ложь"}.get(str(vb).lower(), vb)
    if info.get("valueDecimal") not in (None, ""):
        return info["valueDecimal"]
    if info.get("valueDate") not in (None, ""):
        return info["valueDate"]
    if info.get("pres") not in (None, ""):
        return _b64(info["pres"])
    return info


async def _eval_placeholders(client, target_id, exprs):
    out = {}
    for expr in exprs:
        try:
            raw = await client.eval_expression(
                expression=expr, target_uuid=target_id, stack_level=0,
            )
            out[expr] = _scalar(raw)
        except Exception as exc:
            out[expr] = f"<eval-error: {type(exc).__name__}>"
    return out


def _render(template, evaluated):
    msg = template
    for expr, value in evaluated.items():
        msg = msg.replace("{" + expr + "}", str(value))
    return msg


def _write_jsonl(log_dir: Path, session_id: str, entry: dict) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    path = log_dir / f"{session_id}.jsonl"
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


async def _eval_log_continue(client, target_id, key, template, log_dir):
    """Deferred logpoint body: eval (ping_loop now free) -> log JSONL -> Continue.

    Runs in its own task so the ping_loop can deliver the async `exprEvaluated`
    events that eval_expression awaits. Always Continue in finally — a stuck
    logpoint must never freeze the target.
    """
    try:
        evaluated = await _eval_placeholders(
            client, target_id, extract_placeholders(template))
        entry = {
            "ts": datetime.now().isoformat(),
            "target_id": target_id,
            "object_id": key[0], "property_id": key[1], "line": key[2],
            "template": template,
            "rendered": _render(template, evaluated),
            "evaluated": evaluated,
        }
        session_id = getattr(client, "session_id", None) or "unknown"
        try:
            _write_jsonl(log_dir, session_id, entry)
        except Exception as e:
            log.warning("logpoint JSONL write failed (%s): %s", log_dir, e)
    except Exception as e:
        log.warning("logpoint eval failed for target=%s: %s", target_id[:8], e)
    finally:
        try:
            await client.step("Continue", target_id)
        except Exception as e:
            log.warning("logpoint auto-Continue failed for target=%s: %s",
                        target_id[:8], e)


async def fire_logpoint(client, target_id: str, stack: list, log_dir: Path) -> bool:
    """If current stop is a logpoint -> schedule deferred render/log/Continue.

    Returns True immediately (suppresses user-visible stop). The eval+log+Continue
    is deferred to a separate task (create_task) to break the re-entrancy deadlock:
    eval_expression awaits `exprEvaluated` delivered by ping_loop's _handle_command,
    which cannot run while we are inside it. (Fix 2026-06-04.)
    """
    key = _top_key(stack)
    if key is None or key not in client._logpoints:
        return False
    template = client._logpoints[key]
    task = asyncio.create_task(
        _eval_log_continue(client, target_id, key, template, log_dir))
    _active_tasks.add(task)
    task.add_done_callback(_active_tasks.discard)
    return True