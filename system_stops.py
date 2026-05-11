"""P0.D + P0.E roadmap 260511: filter system stops + BP-propagation drain.

P0.D — Closes cascade-halt: stops with `stopByBP=false` AND no
`_break_on_next_armed` → auto-Continue silently.

P0.E — When a freshly-attached rphost's first stop arrives BEFORE BPs
propagate from dbgs.exe (RDBG async push race), the cascade halt becomes
a synchronization window (CDP `waitForDebuggerOnStart` analogue): wait
~150ms for dbgs→rphost BP push, then Continue. Subsequent BP hits on the
same target proceed normally.
"""
import asyncio
import logging

log = logging.getLogger("1c-debug-mcp.system-stops")


BP_PROPAGATION_WAIT_SEC = 0.15


async def maybe_auto_continue_system_stop(client, target_id, stop_by_bp) -> bool:
    """Returns True iff stop was system-initiated and got auto-Continued.

    P0.E: if target is in `_attached_pending` (freshly attached), this halt
    is the BP-propagation window — wait briefly, reapply BPs, then Continue.

    P0.G: if `_break_on_next_silent_arm` is True, this halt is the warm-pool
    arming window — attach target to session, drain BPs, Continue invisibly.
    """
    if stop_by_bp:
        client_drained_targets = getattr(client, "_attached_pending", None)
        if client_drained_targets is not None:
            client_drained_targets.discard(target_id)
        return False
    if getattr(client, "_break_on_next_silent_arm", False):
        client._break_on_next_silent_arm = False  # one-shot
        try:
            await client.attach_debug_targets([target_id], attach=True)
            client._known_attached_targets.add(target_id)
        except Exception as e:
            log.warning("[P0.G] silent-arm attach failed: %s", e)
        pending = getattr(client, "_attached_pending", None)
        if pending is not None:
            pending.discard(target_id)  # housekeeping: avoid double-drain
        log.info("[P0.G] silent-armed warm rphost target=%s", target_id[:8])
        await _drain_bp_propagation(client, target_id)
        return True
    if getattr(client, "_break_on_next_armed", False):
        return False
    pending = getattr(client, "_attached_pending", None)
    if pending is not None and target_id in pending:
        await _drain_bp_propagation(client, target_id)
        pending.discard(target_id)
        return True
    try:
        await client.step("Continue", target_id)
        log.info("[P0.D] auto-Continue system stop on target=%s", target_id[:8])
        return True
    except Exception as e:
        log.warning("[P0.D] auto-Continue system stop failed: %s — keeping visible", e)
        return False


async def _drain_bp_propagation(client, target_id):
    """P0.E: wait for dbgs→rphost BP push, then Continue (sync window pattern)."""
    try:
        if getattr(client, "_set_breakpoints_cache", None):
            try:
                await client._reapply_bp_workspace()
            except Exception as e:
                log.warning("[P0.E] BP re-apply failed: %s", e)
        await asyncio.sleep(BP_PROPAGATION_WAIT_SEC)
        await client.step("Continue", target_id)
        log.info("[P0.E] drained BPs for target=%s, sleep=%.2fs",
                 target_id[:8], BP_PROPAGATION_WAIT_SEC)
    except Exception as e:
        log.warning("[P0.E] drain failed for target=%s: %s", target_id[:8], e)
