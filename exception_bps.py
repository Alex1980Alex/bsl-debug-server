"""P3.B roadmap 260511: Exception breakpoint filters for `rteProcessing` events.

Default behavior (empty filter list): halt on ALL exceptions (backward compat).
Filter list non-empty: halt ONLY if some filter matches; otherwise auto-Continue.

Each filter is a dict: `{message_pattern: str, module_pattern: str}`.
Both patterns are case-insensitive substring matches (not regex — simple/predictable).
Empty pattern fields = "match anything" for that axis.
"""
from __future__ import annotations

import logging

log = logging.getLogger("1c-debug-mcp.exception-bps")


def should_halt(filters: list, exc_info: dict, stack: list) -> bool:
    """Return True iff at least one filter matches (or filter list is empty)."""
    if not filters:
        return True  # default: halt all exceptions
    msg = _extract_message(exc_info).lower()
    top_module = _extract_top_module_name(stack).lower()
    for f in filters:
        mp = (f.get("message_pattern") or "").lower()
        modp = (f.get("module_pattern") or "").lower()
        if mp and mp not in msg:
            continue
        if modp and modp not in top_module:
            continue
        return True
    return False


def _extract_message(exc_info) -> str:
    if not isinstance(exc_info, dict):
        return ""
    for key in ("messageText", "message", "text", "description"):
        v = exc_info.get(key)
        if isinstance(v, str) and v:
            return v
    return ""


def _extract_top_module_name(stack) -> str:
    top = stack[0] if isinstance(stack, list) and stack else None
    if not isinstance(top, dict):
        return ""
    pres = top.get("presentation", "")
    if isinstance(pres, str):
        return pres
    return ""


async def maybe_suppress(client, target_id, exc_info, stack) -> bool:
    """If filters defined and none match → auto-Continue, return True (suppressed)."""
    filters = getattr(client, "_exception_bp_filters", None) or []
    if not filters:
        return False
    if should_halt(filters, exc_info, stack):
        return False
    try:
        await client.step("Continue", target_id)
        client._stopped_targets.discard(target_id)
        client._last_exception_by_target.pop(target_id, None)
        log.info("[P3.B] exception suppressed (filtered) on target=%s", target_id[:8])
    except Exception as e:
        log.warning("[P3.B] suppress auto-Continue failed: %s", e)
        return False
    return True
