"""P2.A roadmap 260511: snapshot recording + replay seek.

NOT true time-travel (RDBG can't rewind rphost execution). What this provides:
- Record state on each stop event (timestamp, target, stack, exception, reason)
  into `data/debug_replays/<session_id>.jsonl`
- `replay_seek(index)` returns the indexed snapshot for post-mortem inspection
- `replay_list()` returns summary of all snapshots

ROI: GKSTCPLK-2468 «не смогли воспроизвести» — snapshot replay allows
reconstructing past stops without re-running the failing scenario.
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path

log = logging.getLogger("1c-debug-mcp.snapshot")


def record(
    client,
    target_id: str,
    reason: str,
    stack: list,
    exc_info: dict | None = None,
    variables: dict | None = None,
):
    """Append a snapshot entry to the session's replay JSONL.

    C6.2 roadmap 260708 §8.5: `variables` (opt-in, bounded top-K locals captured
    by the caller in a deferred task — eval can't run inline in _handle_command)
    and `correlation_id` (A6.3) are recorded when present, enabling A4 state-level
    diff and correlated-artifact grep.
    """
    if not getattr(client, "_recording_enabled", False):
        return
    session_id = getattr(client, "session_id", None) or "unknown"
    replay_dir = Path(__file__).parent / "data" / "debug_replays"
    try:
        replay_dir.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        log.warning("[P2.A] replay dir create failed: %s", e)
        return
    seq = getattr(client, "_snapshot_seq", 0)
    client._snapshot_seq = seq + 1
    entry = {
        "ts": time.time(),
        "iso": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()),
        "session_id": session_id,
        "correlation_id": getattr(client, "_correlation_id", None),
        "label": getattr(client, "_record_label", None),
        "stop_seq": seq,  # A4.1 monotonic per-session stop ordinal
        "target_id": target_id,
        "reason": reason,
        "stack": stack,
        "exception": exc_info,
        "variables": variables,
    }
    path = replay_dir / f"{session_id}.jsonl"
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as e:
        log.warning("[P2.A] snapshot write failed: %s", e)


def list_snapshots(session_id: str) -> list:
    """Read replay JSONL → return list of summary dicts."""
    if not session_id:
        return []
    path = Path(__file__).parent / "data" / "debug_replays" / f"{session_id}.jsonl"
    if not path.exists():
        return []
    out = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                top = (e.get("stack") or [{}])[0]
                if not isinstance(top, dict):
                    top = {}
                out.append({
                    "index": idx,
                    "iso": e.get("iso", ""),
                    "target_id": (e.get("target_id") or "")[:8],
                    "reason": e.get("reason", ""),
                    "line": top.get("lineNo", ""),
                    "has_exception": bool(e.get("exception")),
                })
    except Exception as e:
        log.warning("[P2.A] list_snapshots read failed: %s", e)
    return out


def seek_snapshot(session_id: str, index: int) -> dict | None:
    """Read replay JSONL → return Nth snapshot (full entry). None if out of range."""
    if not session_id:
        return None
    path = Path(__file__).parent / "data" / "debug_replays" / f"{session_id}.jsonl"
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f):
                if idx != index:
                    continue
                line = line.strip()
                if not line:
                    return None
                return json.loads(line)
    except Exception as e:
        log.warning("[P2.A] seek_snapshot read failed: %s", e)
    return None


# ---------------------------------------------------------------------------
# C6.3 roadmap 260708 §8.5: semantic replay-seek (predicate over snapshots)
# ---------------------------------------------------------------------------

# Special snapshot fields addressable by a seek predicate (not a captured local).
_SPECIAL_FIELDS = ("line", "reason", "module", "fqn")

# Longest operators first so `<=`/`>=`/`<>` aren't split as `<`/`>`.
_SEEK_OPS = ("<=", ">=", "<>", "!=", "==", "=", "<", ">")


def parse_seek_query(query: str):
    """Parse `<name> <op> <literal>` (e.g. `Итог < 0`, `reason = exception`).

    Returns (name, op, literal) or None. `name` may be a captured local OR a
    special field (line/reason/module/fqn). Never raises.
    """
    if not query or not str(query).strip():
        return None
    s = str(query).strip()
    for op in _SEEK_OPS:
        idx = s.find(op)
        if idx > 0:  # name must be non-empty (idx>0), so `= x` alone is rejected
            name = s[:idx].strip()
            literal = s[idx + len(op):].strip()
            if name and literal:
                return (name, op, literal)
    return None


def _entry_field(entry: dict, name: str):
    """Resolve a predicate name → value from a snapshot entry.

    Special fields: `line` (innermost frame lineNo), `reason`, `module`/`fqn`
    (innermost frame resolved_source). Otherwise a captured local from
    `variables`. Returns None if absent.
    """
    low = name.lower()
    stack = entry.get("stack") or []
    # RDBG callStack is outermost-first → innermost (fault/current) frame = LAST.
    innermost = stack[-1] if stack and isinstance(stack[-1], dict) else {}
    if low == "reason":
        return entry.get("reason")
    if low == "line":
        return innermost.get("lineNo")
    if low in ("module", "fqn"):
        rs = innermost.get("resolved_source") if isinstance(innermost.get("resolved_source"), dict) else {}
        return rs.get("fqn")
    variables = entry.get("variables")
    if isinstance(variables, dict):
        # case-insensitive local lookup
        for k, v in variables.items():
            if str(k).lower() == low:
                return v
    return None


def match_entry(entry: dict, predicate) -> bool:
    """True if a snapshot entry satisfies (name, op, literal) — C6.3.

    Delegates the comparison to watchpoints.match_predicate (shared numeric/
    boolean/string comparator). A snapshot missing the field (no captured local /
    special) never matches. Never raises.
    """
    if not predicate:
        return False
    name, op, literal = predicate
    val = _entry_field(entry, name)
    if val is None:
        return False
    try:
        import watchpoints

        return watchpoints.match_predicate(val, op, literal)
    except Exception:
        return False


def seek_by_query(session_id: str, query: str) -> dict | None:
    """C6.3: return the FIRST snapshot whose state satisfies `query`.

    `{index, ...entry}` or None if nothing matches / no session. The numeric
    `index` is preserved on the returned entry so the caller can re-seek by index.
    """
    predicate = parse_seek_query(query)
    if not predicate:
        return None
    for snap in _iter_snapshots(session_id):
        if match_entry(snap["entry"], predicate):
            out = dict(snap["entry"])
            out["index"] = snap["index"]
            return out
    return None


def read_entries(session_id: str) -> list:
    """A4: full snapshot entries for a session in record order (chronological)."""
    return [s["entry"] for s in _iter_snapshots(session_id)]


def _iter_snapshots(session_id: str):
    """Yield {index, entry} for each snapshot in the session JSONL."""
    if not session_id:
        return
    path = Path(__file__).parent / "data" / "debug_replays" / f"{session_id}.jsonl"
    if not path.exists():
        return
    try:
        with open(path, encoding="utf-8") as f:
            for idx, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                try:
                    yield {"index": idx, "entry": json.loads(line)}
                except json.JSONDecodeError:
                    continue
    except OSError as e:
        log.warning("[C6.3] snapshot iterate failed: %s", e)
