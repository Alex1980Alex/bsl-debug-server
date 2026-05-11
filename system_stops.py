"""P0.D roadmap 260511: filter system-initiated stops (spawn-halt, stop_on_next).

Closes cascade-halt issue where `recycle_strategy="all_rphosts_of_ib"` causes
every freshly-spawned rphost to halt at first BSL line (RDBG stop_on_next
attach semantics). Heuristic: stops with `stopByBP=false` AND no
`_break_on_next_armed` are system-initiated → auto-Continue silently.
"""
import logging

log = logging.getLogger("1c-debug-mcp.system-stops")


async def maybe_auto_continue_system_stop(client, target_id, stop_by_bp) -> bool:
    """Returns True iff stop was system-initiated and got auto-Continued."""
    if stop_by_bp:
        return False
    if getattr(client, "_break_on_next_armed", False):
        return False
    try:
        await client.step("Continue", target_id)
        log.info("[P0.D] auto-Continue system stop on target=%s", target_id[:8])
        return True
    except Exception as e:
        log.warning("[P0.D] auto-Continue system stop failed: %s — keeping visible", e)
        return False
