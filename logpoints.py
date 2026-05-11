"""P0.B roadmap 260511: logpoint message rendering + log emission helper."""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime
from pathlib import Path

log = logging.getLogger("1c-debug-mcp.logpoints")


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


async def _eval_placeholders(client, target_id, exprs):
    out = {}
    for expr in exprs:
        try:
            out[expr] = await client.evaluate(
                expression=expr, target_uuid=target_id, stack_level=0,
            )
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


async def fire_logpoint(client, target_id: str, stack: list, log_dir: Path) -> bool:
    """If current stop is a logpoint → render, log, auto-Continue; return True."""
    key = _top_key(stack)
    if key is None or key not in client._logpoints:
        return False
    template = client._logpoints[key]
    evaluated = await _eval_placeholders(client, target_id, extract_placeholders(template))
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
    try:
        await client.step(target_id, "Continue", simple=True)
        client._stopped_targets.discard(target_id)
    except Exception as e:
        log.warning("logpoint auto-Continue failed for target=%s: %s", target_id[:8], e)
    return True
