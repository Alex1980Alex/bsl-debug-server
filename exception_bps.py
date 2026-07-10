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
    modules = [m.lower() for m in _extract_module_names(stack)]
    for f in filters:
        mp = (f.get("message_pattern") or "").lower()
        modp = (f.get("module_pattern") or "").lower()
        if mp and mp not in msg:
            continue
        # H-3 (audit 260710): match module_pattern against ANY frame, not just
        # stack[0]. RDBG callStack is OUTERMOST-first (fault frame is LAST, Ф-2),
        # so keying on stack[0] compared the entry-point JOB module, not the
        # throwing one → the filter never matched → maybe_suppress auto-Continue'd
        # exactly the exception it meant to catch (same class of bug already fixed
        # for message_pattern via `info`). "module X" filter = "X is in the throw
        # path" is the useful semantics anyway.
        if modp and not any(modp in m for m in modules):
            continue
        return True
    return False


def _extract_message(exc_info) -> str:
    if not isinstance(exc_info, dict):
        return ""
    # `info` added 2026-07-10 (A2 code-verify): live rteProcessing carries the
    # message text in `info` (see autonomy.extract_exception_symptom); without it
    # a message_pattern filter never matched real exceptions → suppressed exactly
    # the exception it was meant to catch. Aligned with extract_exception_symptom.
    for key in ("messageText", "message", "info", "text", "description", "descr"):
        v = exc_info.get(key)
        if isinstance(v, str) and v:
            return v
    return ""


def _extract_module_names(stack) -> list:
    """Presentations of ALL frame modules (Ф-2-agnostic — see should_halt)."""
    out: list = []
    if isinstance(stack, list):
        for fr in stack:
            if isinstance(fr, dict):
                pres = fr.get("presentation", "")
                if isinstance(pres, str) and pres:
                    out.append(pres)
    return out


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
