"""P0.A roadmap 260511: hit-condition evaluation + auto-Continue helper."""
import logging

log = logging.getLogger("1c-debug-mcp.bp-conditions")


def eval_hit_condition(cond: str, n: int) -> bool:
    """VS Code DAP syntax: `>N`/`>=N`/`<N`/`<=N`/`=N`/`%N`."""
    c = (cond or "").strip().lstrip("=")
    if not c:
        return True
    try:
        if c.startswith(">="): return n >= int(c[2:])
        if c.startswith("<="): return n <= int(c[2:])
        if c.startswith(">"):  return n > int(c[1:])
        if c.startswith("<"):  return n < int(c[1:])
        if c.startswith("%"):
            m = int(c[1:]); return m > 0 and n % m == 0
        return n == int(c)
    except (ValueError, TypeError):
        return True


async def auto_continue_if_unsatisfied(client, target_id, stack):
    """Returns True iff BP suppressed (counter advanced + auto-Continue done).

    RDBG callStackFormed присылает стек outermost-first: фрейм остановки —
    ПОСЛЕДНИЙ элемент, поэтому фреймы сканируются с конца (innermost-first).
    """
    if not isinstance(stack, list):
        return False
    for frame in reversed(stack):
        if not isinstance(frame, dict):
            continue
        mod = frame.get("moduleID") if isinstance(frame.get("moduleID"), dict) else {}
        try:
            line = int(frame.get("lineNo", 0))
        except (TypeError, ValueError):
            continue
        key = (mod.get("objectID", ""), mod.get("propertyID", ""), line)
        if key in client._hit_conditions:
            return await _do_check(client, target_id, mod, line)
    return False


async def _do_check(client, target_id, mod, line):
    key = (mod.get("objectID", ""), mod.get("propertyID", ""), line)
    if key not in client._hit_conditions: return False
    client._hit_counters[key] = client._hit_counters.get(key, 0) + 1
    if eval_hit_condition(client._hit_conditions[key], client._hit_counters[key]):
        return False
    try:
        await client.step("Continue", target_id)
    except Exception as e:
        log.warning("auto-Continue failed for target=%s: %s", target_id[:8], e)
        return False
    return True
