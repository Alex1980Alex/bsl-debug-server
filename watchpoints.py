"""C4 roadmap 260708 §8.4: data breakpoint / watchpoint (RDBG has no native one).

Emulated on top of the same machinery as logpoints/coverage: a watchpoint is a
plain wrapper-side BP on each assignment line of a variable. On fire, a deferred
task (ping_loop stays free — same re-entrancy fix as logpoints) evaluates the
watched name in the stopped frame, compares it to the previously seen value and,
depending on the mode:

- `record_only`       — append change record + auto-Continue (never halts);
- `break_on_first_change` — on the FIRST change leave the target halted (user-visible);
- `break_when`        — on a change whose new value satisfies a predicate leave it halted.

Standalone like logpoints/coverage — receives `client`, imports nothing from
mcp_debug_server (avoids circular import). Zero behaviour change until a
watchpoint is armed: the `_handle_command` gate is guarded by `client._watchpoints`
which is empty by default.

SECURITY: the watched name is evaluated as BSL in the running rphost (same as
logpoints / eval) — do not arm on untrusted names/expressions.
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path

log = logging.getLogger("1c-debug-mcp.watchpoints")

# Strong refs to in-flight deferred watch tasks (asyncio keeps only a weak ref
# to create_task results). Mirrors logpoints._active_tasks.
_active_tasks: set = set()

# Sentinel for "no prior value yet" — distinct from a legitimately watched
# Неопределено/None so the FIRST observation is recorded as old=None, changed=True
# (roadmap C4.6 acceptance: 1-я запись old=None).
_UNSEEN = object()

# Default per-line fire cap (hot loop guard — same magnitude as coverage).
DEFAULT_MAX_FIRES = 200

_VALID_MODES = ("record_only", "break_on_first_change", "break_when")


async def drain_active(timeout: float = 2.0) -> int:
    """Await in-flight deferred watch tasks (mirror of logpoints.drain_active).

    A collector that reads the JSONL immediately can truncate the tail — the
    last hit's write may still be pending. Returns how many are STILL pending
    after the bounded wait.
    """
    pending = [t for t in list(_active_tasks) if not t.done()]
    if pending:
        await asyncio.wait(pending, timeout=timeout)
    return sum(1 for t in pending if not t.done())


def _frame_keys(stack):
    """(oid, pid, line) per frame, innermost-first (RDBG callStack outermost-first)."""
    if not isinstance(stack, list):
        return
    for frame in reversed(stack):
        if not isinstance(frame, dict):
            continue
        mod = frame.get("moduleID") if isinstance(frame.get("moduleID"), dict) else {}
        try:
            line = int(frame.get("lineNo", 0))
        except (TypeError, ValueError):
            continue
        yield (mod.get("objectID", ""), mod.get("propertyID", ""), line)


def _norm(v) -> str:
    """Normalize a value to a trimmed string for comparison (None-safe)."""
    return "" if v is None else str(v).strip()


def _to_number(s: str):
    """Parse a BSL numeric literal (accepts ',' or '.' decimal). None on failure."""
    t = _norm(s).replace(",", ".")
    if not t:
        return None
    try:
        return float(t)
    except (TypeError, ValueError):
        return None


def match_predicate(value, op: str, literal: str) -> bool:
    """Compare a captured value against `<op> <literal>` (C4 break_when / shared).

    Operators: `=`, `==`, `<>`, `!=`, `<`, `>`, `<=`, `>=`. Numeric comparison
    when both sides parse as numbers; otherwise case-insensitive string equality
    for `=`/`<>` and lexicographic order for the rest. Boolean literals
    (Истина/Ложь/True/False) normalize. Unknown op → False (never raises).
    """
    a = _norm(value)
    b = _norm(literal)
    op = (op or "").strip()
    # Boolean normalization for equality operators.
    bool_map = {"истина": "t", "true": "t", "да": "t", "ложь": "f", "false": "f", "нет": "f"}
    if op in ("=", "=="):
        ma, mb = bool_map.get(a.lower()), bool_map.get(b.lower())
        if ma is not None and mb is not None:
            return ma == mb
        na, nb = _to_number(a), _to_number(b)
        if na is not None and nb is not None:
            return na == nb
        return a.lower() == b.lower()
    if op in ("<>", "!="):
        return not match_predicate(value, "=", literal)
    na, nb = _to_number(a), _to_number(b)
    if na is not None and nb is not None:
        if op == "<":
            return na < nb
        if op == ">":
            return na > nb
        if op == "<=":
            return na <= nb
        if op == ">=":
            return na >= nb
        return False
    # string ordering fallback
    if op == "<":
        return a < b
    if op == ">":
        return a > b
    if op == "<=":
        return a <= b
    if op == ">=":
        return a >= b
    return False


def parse_break_when(expr: str):
    """Parse a `break_when` predicate string `<op> <literal>` (name implicit).

    Examples: "= 0", "<> Истина", "< 0", ">= 100". Returns (op, literal) or None.
    A leading variable name is tolerated and ignored (`Итог = 0` → ("=", "0")).
    """
    if not expr or not str(expr).strip():
        return None
    s = str(expr).strip()
    # Longest operators first so `<=`/`>=`/`<>` aren't split as `<`/`>`.
    for op in ("<=", ">=", "<>", "!=", "==", "=", "<", ">"):
        idx = s.find(op)
        if idx != -1:
            literal = s[idx + len(op):].strip()
            if literal:
                return (op, literal)
    return None


def plan_watchpoints(source_lines: list, name: str, find_assignment_lines, method_range=None) -> list:
    """C4.1: assignment lines `name = ...` in scope (delegates to A3 scanner).

    `find_assignment_lines` is passed in (autonomy.find_assignment_lines) to keep
    this module free of a mcp_debug_server import. Returns the scanner's list
    [{line, text, rhs, upstream}].
    """
    return find_assignment_lines(source_lines, name, method_range, upstream=False)


async def fire_watchpoint(client, target_id: str, stack: list, log_dir: Path) -> bool:
    """If the current stop is a watchpoint line → schedule deferred compare/record.

    Returns True immediately (suppresses the user-visible stop path in
    _handle_command — the deferred task decides Continue vs promote-to-visible).
    Returns False if no watchpoint matches (the stop is handled downstream).

    Mirrors logpoints.fire_logpoint: the eval must run in its own task because
    eval_expression awaits an `exprEvaluated` event delivered by the ping_loop's
    _handle_command, which cannot run while we are inside it.
    """
    watch = getattr(client, "_watchpoints", None)
    if not watch:
        return False
    key = next((k for k in _frame_keys(stack) if k in watch), None)
    if key is None:
        return False
    wp = watch[key]
    task = asyncio.create_task(_compare_and_decide(client, target_id, key, wp, log_dir))
    _active_tasks.add(task)
    task.add_done_callback(_active_tasks.discard)
    return True


def _write_jsonl(log_dir: Path, session_id: str, entry: dict) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    path = log_dir / f"{session_id}.watch.jsonl"
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


async def _compare_and_decide(client, target_id, key, wp, log_dir) -> None:
    """Deferred watch body: eval name → compare → record → (Continue | halt)."""
    name = wp["name"]
    mode = wp.get("mode", "record_only")
    should_continue = True
    try:
        wp["fires"] = wp.get("fires", 0) + 1
        capped = wp["fires"] > wp.get("max_fires", DEFAULT_MAX_FIRES)
        # Even when capped we still Continue (never freeze) but skip eval/record.
        if capped:
            wp["capped"] = True
            return
        # Import here to avoid a hard dependency cycle at module load; logpoints
        # provides the same value-scalarization used everywhere else.
        import logpoints

        try:
            raw = await client.eval_expression(
                expression=name, target_uuid=target_id, stack_level=0
            )
            new_val = logpoints._scalar(raw)
        except Exception as exc:
            new_val = f"<eval-error: {type(exc).__name__}>"

        # F-5 (re-audit 260712): key change-detection by (target_id, name), not
        # `name` alone — parallel rphosts running the same code would otherwise
        # interleave old/new across targets and mis-detect changes.
        last = getattr(client, "_watch_last", {})
        last_key = (target_id, name)
        old = last.get(last_key, _UNSEEN)
        first = old is _UNSEEN
        changed = first or (_norm(new_val) != _norm(old))
        last[last_key] = new_val
        client._watch_last = last

        record = {
            "ts": datetime.now().isoformat(),
            "target_id": target_id,
            "object_id": key[0],
            "property_id": key[1],
            "line": key[2],
            "name": name,
            "old": None if first else old,
            "new": new_val,
            "changed": changed,
            "run_id": wp.get("run_id"),
        }
        if changed:
            changes = getattr(client, "_watch_changes", [])
            changes.append(record)
            client._watch_changes = changes
            session_id = getattr(client, "session_id", None) or "unknown"
            try:
                _write_jsonl(log_dir, session_id, record)
            except Exception as e:
                log.warning("watchpoint JSONL write failed (%s): %s", log_dir, e)

        # Decide whether to leave the target halted (user-visible).
        halt = False
        if changed:
            if mode == "break_on_first_change":
                halt = True
            elif mode == "break_when":
                pred = wp.get("predicate")  # (op, literal) tuple
                if pred and match_predicate(new_val, pred[0], pred[1]):
                    halt = True
        if halt:
            should_continue = False
            # Promote to a user-visible stop so an _await_bp_stop waiter / the
            # agent sees the halt (it was suppressed out of the metrics path above).
            try:
                client._user_visible_stops.add(target_id)
                # M-6 parity (review 260712): age-bound the promoted stop so a
                # reconnect/health check doesn't treat this watch-halt as stale.
                import time as _t

                client._last_visible_stop_ts = _t.time()
                # F-4 (re-audit 260712): the watch gate returned early in
                # _handle_command, so this halt bypassed the metrics block. Record
                # it into _stop_events / _watch_halt_count so debug_session_summary
                # doesn't undercount watch-driven halts.
                try:
                    client._stop_events.append(
                        {
                            "ts": record["ts"],
                            "target_id": target_id,
                            "lineNo": key[2],
                            "reason": "watchpoint",
                        }
                    )
                    client._watch_halt_count = getattr(client, "_watch_halt_count", 0) + 1
                    getattr(client, "_rphosts_seen", set()).add(target_id)
                except Exception:
                    log.debug("watchpoint metrics record failed", exc_info=True)
                client._signal_bp_stop()
            except Exception:
                log.debug("watchpoint halt-promote signalling failed", exc_info=True)
            wp["halted_at"] = record
    except Exception as e:
        log.warning("watchpoint compare failed for target=%s: %s", target_id[:8], e)
    finally:
        if should_continue:
            try:
                await client.step("Continue", target_id)
            except Exception as e:
                log.warning("watchpoint auto-Continue failed for target=%s: %s", target_id[:8], e)


def read_timeline(log_dir: Path, session_id: str, run_id, keys: set, skip_lines: int) -> list:
    """Read the watch JSONL → change records for this run (keys ∈ armed lines).

    Filters by (object_id, property_id, line) ∈ keys and skips the first
    `skip_lines` entries (pre-arm). Returns records in file (chronological) order.
    """
    path = Path(log_dir) / f"{session_id}.watch.jsonl"
    if not path.exists():
        return []
    try:
        raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as e:
        log.warning("watchpoint read_timeline failed (%s): %s", path, e)
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
        if keys and k not in keys:
            continue
        # Filter by run_id too (review 260712): a prior run's late deferred write
        # can share a (oid,pid,line) key with a re-armed run; skip_lines alone
        # doesn't exclude it. Records carry run_id, so match it when provided.
        if run_id is not None and e.get("run_id") not in (None, run_id):
            continue
        out.append(e)
    return out
