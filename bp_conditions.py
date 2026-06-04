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
    """Returns True iff BP suppressed (counter advanced + auto-Continue done)."""
    top = stack[0] if isinstance(stack, list) and stack else None
    if not isinstance(top, dict): return False
    mod = top.get("moduleID") if isinstance(top.get("moduleID"), dict) else {}
    try:
        line = int(top.get("lineNo", 0))
    except (TypeError, ValueError):
        return False
    return await _do_check(client, target_id, mod, line)


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
