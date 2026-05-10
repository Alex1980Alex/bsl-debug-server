"""Unit tests for mcp_debug_server.py — roadmap §13 P3.1.

Strategy: pure-logic + state-machine focus. Patch `RDBGClient._post` to
isolate from HTTP layer; verify event dispatch, target resolution,
idempotent re-attach, and stack/exception caching.

Coverage targets (lines 134..654 of mcp_debug_server.py):
- _extract_target_id (UUID-validated classmethod)
- _resolve_target_uuid (fallback chain)
- _handle_command (14 cmdId types)
- _ensure_target_attached (idempotency)
- get_call_stack (cache-hit + ensure-attached fallback)
- step.Continue resume semantics (drops _stopped_targets,
  _last_stopped_target_id, _last_exception_by_target)
- last_stopped_target_id public property
"""

from __future__ import annotations

import asyncio
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Make the package importable from the test directory
sys.path.insert(0, str(Path(__file__).parent.parent))

import mcp_debug_server as mds
from mcp_debug_server import RDBGClient


GOOD_UUID = "11111111-2222-3333-4444-555555555555"
ANOTHER_UUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
NOT_A_UUID = "queue-id-not-a-uuid"


# ---------------------------------------------------------------------------
# _extract_target_id — UUID-validated classmethod
# ---------------------------------------------------------------------------

class TestExtractTargetId:
    def test_flat_string_valid_uuid(self):
        assert RDBGClient._extract_target_id({"targetID": GOOD_UUID}) == GOOD_UUID

    def test_flat_string_uppercase_uuid(self):
        upper = GOOD_UUID.upper()
        assert RDBGClient._extract_target_id({"targetID": upper}) == upper

    def test_flat_string_invalid_uuid_rejected(self):
        # Reviewer-fix: previously last-resort fallback returned non-UUID strings
        assert RDBGClient._extract_target_id({"targetID": NOT_A_UUID}) is None

    def test_nested_struct_id_field(self):
        cmd = {"targetID": {"_tag": "DebugTargetIdStr", "id": GOOD_UUID}}
        assert RDBGClient._extract_target_id(cmd) == GOOD_UUID

    def test_nested_struct_value_field(self):
        cmd = {"targetID": {"_tag": "x", "_value": GOOD_UUID}}
        assert RDBGClient._extract_target_id(cmd) == GOOD_UUID

    def test_nested_invalid_returns_none(self):
        cmd = {"targetID": {"_tag": "x", "id": "not-uuid", "_value": "also-not"}}
        assert RDBGClient._extract_target_id(cmd) is None

    def test_targetidstr_alternate_key(self):
        cmd = {"targetIDStr": GOOD_UUID}
        assert RDBGClient._extract_target_id(cmd) == GOOD_UUID

    def test_no_keys_returns_none(self):
        assert RDBGClient._extract_target_id({"_tag": "Something", "x": "y"}) is None

    def test_empty_dict(self):
        assert RDBGClient._extract_target_id({}) is None

    def test_other_field_with_uuid_not_picked(self):
        # Other UUID-shaped fields (requestQueueID etc.) must NOT be returned
        # — only `targetID` / `targetIDStr` are honoured.
        cmd = {"requestQueueID": GOOD_UUID, "_tag": "Foo"}
        assert RDBGClient._extract_target_id(cmd) is None


# ---------------------------------------------------------------------------
# Fixtures: client with patched _post
# ---------------------------------------------------------------------------

@pytest.fixture
def client():
    """RDBGClient instance — _post patched to AsyncMock returning empty Element."""
    c = RDBGClient(debug_url="http://localhost:1550", infobase_alias="TestDB")
    c._post = AsyncMock(return_value=ET.Element("empty"))
    return c


# ---------------------------------------------------------------------------
# _resolve_target_uuid — fallback chain
# ---------------------------------------------------------------------------

class TestResolveTargetUuid:
    def test_explicit_takes_precedence(self, client):
        client._last_stopped_target_id = ANOTHER_UUID
        assert client._resolve_target_uuid(GOOD_UUID) == GOOD_UUID

    def test_falls_back_to_last_stopped(self, client):
        client._last_stopped_target_id = GOOD_UUID
        assert client._resolve_target_uuid(None) == GOOD_UUID

    def test_returns_none_when_nothing_known(self, client):
        assert client._resolve_target_uuid(None) is None

    def test_empty_string_treated_as_none(self, client):
        client._last_stopped_target_id = GOOD_UUID
        assert client._resolve_target_uuid("") == GOOD_UUID


# ---------------------------------------------------------------------------
# last_stopped_target_id public property (reviewer fix 2026-05-09)
# ---------------------------------------------------------------------------

class TestLastStoppedTargetIdProperty:
    def test_property_exists_and_returns_state(self, client):
        client._last_stopped_target_id = GOOD_UUID
        assert client.last_stopped_target_id == GOOD_UUID

    def test_property_returns_none_initially(self, client):
        assert client.last_stopped_target_id is None

    def test_property_reflects_state_change(self, client):
        client._last_stopped_target_id = GOOD_UUID
        assert client.last_stopped_target_id == GOOD_UUID
        client._last_stopped_target_id = ANOTHER_UUID
        assert client.last_stopped_target_id == ANOTHER_UUID


# ---------------------------------------------------------------------------
# _handle_command — 14 cmdId types
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestHandleCommand:

    async def test_target_started_auto_attaches(self, client):
        client.attach_debug_targets = AsyncMock(return_value=True)
        await client._handle_command({
            "cmdId": "targetStarted",
            "targetID": GOOD_UUID,
        })
        client.attach_debug_targets.assert_awaited_once_with([GOOD_UUID])
        assert GOOD_UUID in client._known_attached_targets

    async def test_target_started_idempotent(self, client):
        client.attach_debug_targets = AsyncMock(return_value=True)
        client._known_attached_targets.add(GOOD_UUID)
        await client._handle_command({
            "cmdId": "targetStarted", "targetID": GOOD_UUID,
        })
        client.attach_debug_targets.assert_not_called()

    async def test_target_started_attach_failure_does_not_pollute_known(self, client):
        client.attach_debug_targets = AsyncMock(side_effect=RuntimeError("RDBG 400"))
        await client._handle_command({
            "cmdId": "targetStarted", "targetID": GOOD_UUID,
        })
        # Failure → target NOT added (next ping will retry)
        assert GOOD_UUID not in client._known_attached_targets

    async def test_target_started_without_target_id_noop(self, client):
        client.attach_debug_targets = AsyncMock()
        await client._handle_command({"cmdId": "targetStarted"})
        client.attach_debug_targets.assert_not_called()

    async def test_call_stack_formed_breakpoint(self, client):
        stack = [{"_tag": "frame", "line": "10"}, {"_tag": "frame", "line": "20"}]
        await client._handle_command({
            "cmdId": "callStackFormed",
            "targetID": GOOD_UUID,
            "callStack": stack,
            "stopByBP": "true",
        })
        assert GOOD_UUID in client._stopped_targets
        assert client._last_stopped_target_id == GOOD_UUID
        assert client._last_stack_by_target[GOOD_UUID] == stack
        assert client._stop_reason_by_target[GOOD_UUID] == "breakpoint"

    async def test_call_stack_formed_step_stop(self, client):
        await client._handle_command({
            "cmdId": "callStackFormed",
            "targetID": GOOD_UUID,
            "callStack": {"_tag": "frame"},  # single-dict normalised to list
            "stopByBP": "false",
        })
        assert client._stop_reason_by_target[GOOD_UUID] == "step"
        assert client._last_stack_by_target[GOOD_UUID] == [{"_tag": "frame"}]

    async def test_call_stack_formed_no_target_skipped(self, client):
        await client._handle_command({
            "cmdId": "callStackFormed",
            "callStack": [],
        })
        assert client._stopped_targets == set()
        assert client._last_stopped_target_id is None

    async def test_rte_processing_caches_exception(self, client):
        exc = {"_tag": "exception", "code": "42", "info": "Деление на ноль"}
        await client._handle_command({
            "cmdId": "rteProcessing",
            "targetID": GOOD_UUID,
            "callStack": [{"_tag": "frame"}],
            "exception": exc,
        })
        assert GOOD_UUID in client._stopped_targets
        assert client._last_stopped_target_id == GOOD_UUID
        assert client._stop_reason_by_target[GOOD_UUID] == "exception"
        assert client._last_exception_by_target[GOOD_UUID] == exc

    async def test_rte_processing_no_target_skipped(self, client):
        await client._handle_command({
            "cmdId": "rteProcessing",
            "callStack": [],
        })
        assert client._stopped_targets == set()
        assert client._last_exception_by_target == {}

    async def test_target_quit_clears_all_state(self, client):
        # Pre-populate state
        client._stopped_targets.add(GOOD_UUID)
        client._last_stack_by_target[GOOD_UUID] = [{"frame": 1}]
        client._stop_reason_by_target[GOOD_UUID] = "breakpoint"
        client._last_exception_by_target[GOOD_UUID] = {"code": "42"}
        client._known_attached_targets.add(GOOD_UUID)

        await client._handle_command({
            "cmdId": "targetQuit", "targetID": GOOD_UUID,
        })

        assert GOOD_UUID not in client._stopped_targets
        assert GOOD_UUID not in client._last_stack_by_target
        assert GOOD_UUID not in client._stop_reason_by_target
        assert GOOD_UUID not in client._last_exception_by_target
        assert GOOD_UUID not in client._known_attached_targets

    async def test_corrected_bp_does_not_change_state(self, client):
        await client._handle_command({
            "cmdId": "correctedBP", "targetID": GOOD_UUID,
        })
        # Just logged a warning, no state mutation
        assert client._stopped_targets == set()

    @pytest.mark.parametrize("cmd_type", [
        "ForegroundHelperSet", "ForegroundHelperRequest",
        "ForegroundHelperProcess", "measureResultProcessing",
        "errorViewInfo", "rteOnBPConditionProcessing",
        "exprEvaluated", "valueModified", "unknown", "",
    ])
    async def test_skipped_cmd_types_no_op(self, client, cmd_type):
        await client._handle_command({"cmdId": cmd_type, "targetID": GOOD_UUID})
        assert client._stopped_targets == set()
        assert client._last_stopped_target_id is None

    async def test_unknown_cmd_type_logged_only(self, client):
        await client._handle_command({"cmdId": "BogusEvent", "targetID": GOOD_UUID})
        assert client._stopped_targets == set()

    async def test_cmdidnum_fallback_target_started(self, client):
        # Real-world finding 2026-05-09 §13.18: RDBG может emit cmdIDNum=1 без cmdId
        client.attach_debug_targets = AsyncMock(return_value=True)
        await client._handle_command({
            "cmdIDNum": "1",  # 1 = targetStarted per DBGUIExtCmds enum
            "targetID": GOOD_UUID,
        })
        client.attach_debug_targets.assert_awaited_once_with([GOOD_UUID])
        assert GOOD_UUID in client._known_attached_targets

    async def test_cmdidnum_fallback_call_stack_formed(self, client):
        await client._handle_command({
            "cmdIDNum": "7",  # 7 = callStackFormed
            "targetID": GOOD_UUID,
            "callStack": [{"_tag": "frame"}],
            "stopByBP": "true",
        })
        assert client._last_stopped_target_id == GOOD_UUID
        assert client._stop_reason_by_target[GOOD_UUID] == "breakpoint"

    async def test_explicit_cmdid_overrides_cmdidnum(self, client):
        # If both present, literal cmdId wins (yukon39 wire format expectation)
        client.attach_debug_targets = AsyncMock(return_value=True)
        await client._handle_command({
            "cmdId": "targetStarted",
            "cmdIDNum": "999",  # bogus ordinal — must be ignored
            "targetID": GOOD_UUID,
        })
        client.attach_debug_targets.assert_awaited_once()


# ---------------------------------------------------------------------------
# _ensure_target_attached — idempotent guard
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestEnsureTargetAttached:
    async def test_attaches_when_unknown(self, client):
        client.attach_debug_targets = AsyncMock(return_value=True)
        await client._ensure_target_attached(GOOD_UUID)
        client.attach_debug_targets.assert_awaited_once_with([GOOD_UUID])
        assert GOOD_UUID in client._known_attached_targets

    async def test_skips_when_known(self, client):
        client.attach_debug_targets = AsyncMock()
        client._known_attached_targets.add(GOOD_UUID)
        await client._ensure_target_attached(GOOD_UUID)
        client.attach_debug_targets.assert_not_called()

    async def test_no_op_when_uuid_empty(self, client):
        client.attach_debug_targets = AsyncMock()
        await client._ensure_target_attached("")
        client.attach_debug_targets.assert_not_called()

    async def test_swallow_attach_exception(self, client):
        client.attach_debug_targets = AsyncMock(side_effect=RuntimeError("boom"))
        # Must NOT raise — error logged, race-window safe
        await client._ensure_target_attached(GOOD_UUID)
        assert GOOD_UUID not in client._known_attached_targets


# ---------------------------------------------------------------------------
# get_call_stack — cache-hit path + pull-fallback ensure-attached
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestGetCallStack:
    async def test_cache_hit_returns_cached_stack(self, client):
        cached = [{"_tag": "frame", "line": "5"}]
        client._last_stack_by_target[GOOD_UUID] = cached
        client.attach_debug_targets = AsyncMock()

        result = await client.get_call_stack(GOOD_UUID)

        assert result == cached
        # No HTTP pull triggered — cache hit
        client._post.assert_not_called()
        client.attach_debug_targets.assert_not_called()

    async def test_cache_miss_pulls_and_ensures_attached(self, client):
        client.attach_debug_targets = AsyncMock(return_value=True)
        # Build minimal RDBG callStack response
        root = ET.Element("root")
        cs = ET.SubElement(root, "callStack")
        ET.SubElement(cs, "line").text = "42"
        client._post = AsyncMock(return_value=root)

        result = await client.get_call_stack(GOOD_UUID)

        client.attach_debug_targets.assert_awaited_once_with([GOOD_UUID])
        client._post.assert_awaited_once()
        assert isinstance(result, list)
        assert len(result) == 1

    async def test_falls_back_to_last_stopped_when_no_uuid(self, client):
        cached = [{"_tag": "frame"}]
        client._last_stopped_target_id = GOOD_UUID
        client._last_stack_by_target[GOOD_UUID] = cached

        result = await client.get_call_stack(None)

        assert result == cached

    async def test_returns_empty_when_no_target_anywhere(self, client):
        result = await client.get_call_stack(None)
        assert result == []
        client._post.assert_not_called()


# ---------------------------------------------------------------------------
# step() — Continue resume semantics + RTE cleanup
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestStepResume:
    async def test_continue_drops_stopped_state(self, client):
        client._stopped_targets.add(GOOD_UUID)
        client._last_stopped_target_id = GOOD_UUID
        client._known_attached_targets.add(GOOD_UUID)

        await client.step(action="Continue", target_uuid=GOOD_UUID)

        assert GOOD_UUID not in client._stopped_targets
        assert client._last_stopped_target_id is None

    async def test_continue_clears_exception_cache(self, client):
        # Reviewer fix: step.Continue from RTE must not leave ghost exception
        client._stopped_targets.add(GOOD_UUID)
        client._last_stopped_target_id = GOOD_UUID
        client._last_exception_by_target[GOOD_UUID] = {"code": "42"}
        client._known_attached_targets.add(GOOD_UUID)

        await client.step(action="Continue", target_uuid=GOOD_UUID)

        assert GOOD_UUID not in client._last_exception_by_target

    async def test_step_uses_last_stopped_when_omitted(self, client):
        client._stopped_targets.add(GOOD_UUID)
        client._last_stopped_target_id = GOOD_UUID
        client._known_attached_targets.add(GOOD_UUID)

        await client.step(action="StepIn")

        # Without target_uuid arg → fallback resolved through cached state
        client._post.assert_awaited_once()

    async def test_step_raises_when_no_target_resolvable(self, client):
        with pytest.raises(ValueError, match="no target_uuid"):
            await client.step(action="Continue")

    async def test_step_only_clears_matching_last_stopped(self, client):
        # If client._last_stopped_target_id != stepped target, do not nullify
        client._last_stopped_target_id = ANOTHER_UUID
        client._stopped_targets.update({GOOD_UUID, ANOTHER_UUID})
        client._known_attached_targets.update({GOOD_UUID, ANOTHER_UUID})

        await client.step(action="Continue", target_uuid=GOOD_UUID)

        assert GOOD_UUID not in client._stopped_targets
        assert ANOTHER_UUID in client._stopped_targets  # still stopped
        assert client._last_stopped_target_id == ANOTHER_UUID  # untouched


# ---------------------------------------------------------------------------
# eval_expression / eval_local_variables — re-attach guard
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestEvalReattach:
    async def test_eval_expression_ensures_attached(self, client):
        client.attach_debug_targets = AsyncMock(return_value=True)
        await client.eval_expression(
            expression="ТекущаяДата()", target_uuid=GOOD_UUID, async_wait_timeout=0,
        )
        client.attach_debug_targets.assert_awaited_once_with([GOOD_UUID])

    async def test_eval_local_variables_uses_last_stopped(self, client):
        client._last_stopped_target_id = GOOD_UUID
        client.attach_debug_targets = AsyncMock(return_value=True)
        # 2026-05-10: eval_local_variables now requires non-empty `expressions`.
        # Empty list is a no-op (returns []) without calling attach.
        await client.eval_local_variables(expressions=["X"], async_wait_timeout=0)
        # Re-attach probed for fallback target
        client.attach_debug_targets.assert_awaited_once_with([GOOD_UUID])

    async def test_eval_local_variables_empty_expressions_returns_empty(self, client):
        # No expressions → no-op, no RDBG call.
        client._last_stopped_target_id = GOOD_UUID
        client.attach_debug_targets = AsyncMock(return_value=True)
        result = await client.eval_local_variables(expressions=[])
        assert result == []
        client.attach_debug_targets.assert_not_awaited()

    async def test_eval_expression_raises_when_no_target(self, client):
        with pytest.raises(ValueError, match="no target_uuid"):
            await client.eval_expression(expression="1+1")

    async def test_eval_uses_max_text_size_4096(self, client):
        # P2.3: composite types pres options bumped from 1000 to 4096
        client.attach_debug_targets = AsyncMock(return_value=True)
        client._last_stopped_target_id = GOOD_UUID
        await client.eval_expression(expression="Контрагент", async_wait_timeout=0)
        # Inspect the XML body that was posted — last positional arg is body
        post_call = client._post.call_args
        body = post_call.args[1] if len(post_call.args) > 1 else post_call.kwargs.get("body", "")
        assert "<debugCalculations:maxTextSize>4096</debugCalculations:maxTextSize>" in body

    async def test_eval_view_interface_opt_in(self, client):
        # P2.3: viewInterface tag included only when explicitly passed
        client.attach_debug_targets = AsyncMock(return_value=True)
        client._last_stopped_target_id = GOOD_UUID
        await client.eval_expression(
            expression="Контрагент.Ссылка", view_interface="context", async_wait_timeout=0,
        )
        body = client._post.call_args.args[1]
        assert "<debugCalculations:viewInterface>context</debugCalculations:viewInterface>" in body

    async def test_eval_no_view_interface_by_default(self, client):
        # Default behavior — viewInterface tag absent (backward compat)
        client.attach_debug_targets = AsyncMock(return_value=True)
        client._last_stopped_target_id = GOOD_UUID
        await client.eval_expression(expression="x", async_wait_timeout=0)
        body = client._post.call_args.args[1]
        assert "viewInterface" not in body

    async def test_eval_custom_max_text_size(self, client):
        client.attach_debug_targets = AsyncMock(return_value=True)
        client._last_stopped_target_id = GOOD_UUID
        await client.eval_expression(expression="БольшаяТаблица", max_text_size=16384,
                                      async_wait_timeout=0)
        body = client._post.call_args.args[1]
        assert "<debugCalculations:maxTextSize>16384</debugCalculations:maxTextSize>" in body


@pytest.mark.asyncio
class TestEvalAsyncPickup:
    """eval_expression async event delivery via _pending_evals + exprEvaluated."""

    async def test_pending_future_registered_before_post(self, client):
        # POST must see the future already in _pending_evals so racing
        # exprEvaluated event from ping_loop can resolve it.
        client.attach_debug_targets = AsyncMock(return_value=True)
        captured_pending = {}

        async def post_capture(cmd, body, **kw):
            # Simulate ping_loop delivering exprEvaluated event mid-POST
            captured_pending.update(client._pending_evals)
            return ET.Element("empty")

        client._post = AsyncMock(side_effect=post_capture)
        await client.eval_expression(expression="x", target_uuid=GOOD_UUID,
                                      async_wait_timeout=0)
        assert len(captured_pending) == 1, "Future must be registered before POST"

    async def test_sync_result_returns_immediately(self, client):
        # If RDBG returned the value inline (calcWaitingTime sufficed),
        # eval_expression skips the wait and returns sync_result.
        client.attach_debug_targets = AsyncMock(return_value=True)
        non_empty = ET.Element("RDBGEvalExprResponse")
        result_elem = ET.SubElement(non_empty, "result")
        ET.SubElement(result_elem, "value").text = "42"
        client._post = AsyncMock(return_value=non_empty)
        result = await client.eval_expression(expression="40+2", target_uuid=GOOD_UUID,
                                               async_wait_timeout=0)
        assert result, "Sync result should not be empty"
        # _pending_evals must be cleaned up
        assert len(client._pending_evals) == 0

    async def test_expr_evaluated_event_resolves_pending_future(self, client):
        # Simulate the ping_loop receiving exprEvaluated event AFTER
        # eval_expression POSTed and is awaiting the future.
        client.attach_debug_targets = AsyncMock(return_value=True)
        client._post = AsyncMock(return_value=ET.Element("empty"))

        async def eval_then_resolve():
            # Wait briefly for eval_expression to register the future, then
            # resolve it via _handle_command (simulating ping_loop event).
            await asyncio.sleep(0.05)
            assert len(client._pending_evals) == 1
            result_id = next(iter(client._pending_evals))
            event = {
                "cmdId": "exprEvaluated",
                "evalExprResBaseData": {
                    "expressionResultID": result_id,
                    "value": "result-payload",
                },
            }
            await client._handle_command(event)

        results = await asyncio.gather(
            client.eval_expression(expression="x", target_uuid=GOOD_UUID,
                                    async_wait_timeout=2.0),
            eval_then_resolve(),
        )
        eval_result = results[0]
        assert eval_result, "Expected non-empty result delivered via event"
        assert eval_result[0]["value"] == "result-payload"
        assert len(client._pending_evals) == 0

    async def test_unknown_result_id_event_is_ignored(self, client):
        # exprEvaluated for a result_id that has no pending future just logs
        # a debug message — must not raise or pollute state.
        await client._handle_command({
            "cmdId": "exprEvaluated",
            "evalExprResBaseData": {"expressionResultID": GOOD_UUID, "value": "ghost"},
        })
        assert len(client._pending_evals) == 0  # nothing changed


@pytest.mark.asyncio
class TestUiPlusRetry:
    """_post auto-recovery when RDBG returns 400 «UI+ часть отладки не зарегистрирована»."""

    async def _restore_real_post(self, client):
        """Fixture's `client` mocks `_post` — restore the real method so the
        UI+ retry logic runs end-to-end via `_http.post` (also mocked here)."""
        from mcp_debug_server import RDBGClient as RealClient
        client._post = RealClient._post.__get__(client, RealClient)

    async def test_retry_re_handshakes_and_succeeds(self, client):
        # First call: RDBG returns 400 UI+ revoked. Wrapper auto re-handshakes
        # (init_settings + clear_break_on_next_statement), retries once, succeeds.
        import httpx as _httpx
        await self._restore_real_post(client)

        ui_plus_400 = _httpx.Response(
            400, content="UI+ - часть отладки не зарегистрирована".encode("utf-8"),
            request=_httpx.Request("POST", "http://test/"),
        )
        ok_resp = _httpx.Response(
            200, content=b"<root/>",
            request=_httpx.Request("POST", "http://test/"),
        )

        client._http = MagicMock()
        # Sequence: setBreakOnNextStatement→400, init_settings→200,
        # clearBreakOnNextStatement→200, retry setBreakOnNextStatement→200
        client._http.post = AsyncMock(side_effect=[ui_plus_400, ok_resp, ok_resp, ok_resp])

        await client.set_break_on_next_statement()
        assert client._http.post.await_count == 4

    async def test_no_retry_for_handshake_commands(self, client):
        # If init_settings ITSELF returns 400 UI+, we MUST NOT recursively retry
        # (would infinite-loop). Test by calling init_settings with mocked 400.
        import httpx as _httpx
        await self._restore_real_post(client)

        ui_plus_400 = _httpx.Response(
            400, content="UI+ - часть отладки не зарегистрирована".encode("utf-8"),
            request=_httpx.Request("POST", "http://test/"),
        )
        client._http = MagicMock()
        client._http.post = AsyncMock(return_value=ui_plus_400)

        with pytest.raises(_httpx.HTTPStatusError, match="initSettings 400"):
            await client.init_settings()
        # Exactly 1 call — no retry attempted
        assert client._http.post.await_count == 1

    async def test_unrelated_400_not_retried(self, client):
        # Other 400 errors (e.g. «Не указан идентификатор предмета отладки»)
        # bubble up as HTTPStatusError without retry.
        import httpx as _httpx
        await self._restore_real_post(client)

        other_400 = _httpx.Response(
            400, content=b"<error>Some other error</error>",
            request=_httpx.Request("POST", "http://test/"),
        )
        client._http = MagicMock()
        client._http.post = AsyncMock(return_value=other_400)

        with pytest.raises(_httpx.HTTPStatusError):
            await client.set_break_on_next_statement()
        assert client._http.post.await_count == 1  # no retry

    async def test_escalation_to_full_reattach_when_light_fails(self, client):
        # Live test 2026-05-10: light handshake retry can ALSO 400 with UI+
        # message → wrapper escalates to full detachDebugUI + new attachDebugUI
        # + 4-step handshake (with fresh session_id). Verify the escalation path.
        import httpx as _httpx
        await self._restore_real_post(client)

        ui_plus_400 = _httpx.Response(
            400, content="UI+ - часть отладки не зарегистрирована".encode("utf-8"),
            request=_httpx.Request("POST", "http://test/"),
        )
        attach_ok = _httpx.Response(
            200,
            content=b"<root><result>registered</result></root>",
            request=_httpx.Request("POST", "http://test/"),
        )
        ok_resp = _httpx.Response(
            200, content=b"<root/>",
            request=_httpx.Request("POST", "http://test/"),
        )

        client._http = MagicMock()
        # Sequence:
        #   1. setBreakOnNextStatement → 400 UI+
        #   2. init_settings (light handshake) → 200
        #   3. clearBreakOnNextStatement → 200
        #   4. setBreakOnNextStatement retry → 400 UI+ AGAIN (light failed)
        #   5. detachDebugUI → 200
        #   6. attachDebugUI (re-attach with fresh session_id) → 200
        #   7. init_settings (full handshake) → 200
        #   8. clearBreakOnNextStatement → 200
        #   9. setAutoAttachSettings → 200
        #   10. setBreakOnNextStatement final retry → 200 SUCCESS
        client._http.post = AsyncMock(side_effect=[
            ui_plus_400, ok_resp, ok_resp,
            ui_plus_400,
            ok_resp, attach_ok, ok_resp, ok_resp, ok_resp,
            ok_resp,
        ])

        old_session_id = client.session_id
        await client.set_break_on_next_statement()
        assert client._http.post.await_count == 10
        # Session ID must have rotated during escalation (fresh attachDebugUI).
        assert client.session_id != old_session_id

    async def test_escalation_when_light_handshake_itself_fails(self, client):
        # Live test 2026-05-10: when UI+ revoked, init_settings ITSELF returns
        # 400 UI+ (not just the original command). Wrapper must skip directly
        # to escalation, not re-raise.
        import httpx as _httpx
        await self._restore_real_post(client)

        ui_plus_400 = _httpx.Response(
            400, content="UI+ - часть отладки не зарегистрирована".encode("utf-8"),
            request=_httpx.Request("POST", "http://test/"),
        )
        attach_ok = _httpx.Response(
            200, content=b"<root><result>registered</result></root>",
            request=_httpx.Request("POST", "http://test/"),
        )
        ok_resp = _httpx.Response(
            200, content=b"<root/>",
            request=_httpx.Request("POST", "http://test/"),
        )

        client._http = MagicMock()
        # Sequence:
        #   1. setBreakOnNextStatement → 400 UI+
        #   2. init_settings (light) → 400 UI+ ← light handshake itself fails!
        #   3. detachDebugUI → 200
        #   4. attachDebugUI (escalation) → 200 registered
        #   5. init_settings (full) → 200
        #   6. clearBreakOnNextStatement → 200
        #   7. setAutoAttachSettings → 200
        #   8. setBreakOnNextStatement final retry → 200 SUCCESS
        client._http.post = AsyncMock(side_effect=[
            ui_plus_400, ui_plus_400,
            ok_resp, attach_ok, ok_resp, ok_resp, ok_resp,
            ok_resp,
        ])

        old_session_id = client.session_id
        await client.set_break_on_next_statement()
        assert client._http.post.await_count == 8
        assert client.session_id != old_session_id

    async def test_escalation_url_includes_attachDebugUI(self, client):
        # Verify the 6th call (after light handshake fail) uses attachDebugUI.
        import httpx as _httpx
        await self._restore_real_post(client)

        ui_plus_400 = _httpx.Response(
            400, content="UI+ - часть отладки не зарегистрирована".encode("utf-8"),
            request=_httpx.Request("POST", "http://test/"),
        )
        attach_ok = _httpx.Response(
            200, content=b"<root><result>registered</result></root>",
            request=_httpx.Request("POST", "http://test/"),
        )
        ok_resp = _httpx.Response(
            200, content=b"<root/>",
            request=_httpx.Request("POST", "http://test/"),
        )

        client._http = MagicMock()
        client._http.post = AsyncMock(side_effect=[
            ui_plus_400, ok_resp, ok_resp,
            ui_plus_400,
            ok_resp, attach_ok, ok_resp, ok_resp, ok_resp,
            ok_resp,
        ])
        await client.set_break_on_next_statement()
        # Call #6 (index 5) must hit attachDebugUI — signals escalation reached re-attach.
        attach_call_url = client._http.post.await_args_list[5].args[0]
        assert "cmd=attachDebugUI" in attach_call_url


# ---------------------------------------------------------------------------
# P2.4 Diagnostic methods (get_breakpoints, get_target_state)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestGetBreakpointsCache:
    async def test_empty_cache_initially(self, client):
        assert await client.get_breakpoints() == []

    async def test_cache_populated_on_set_breakpoints(self, client):
        await client.set_breakpoints(
            module_type="ConfigModule",
            object_id=GOOD_UUID,
            property_id=ANOTHER_UUID,
            lines=[10, 20],
        )
        bps = await client.get_breakpoints()
        assert len(bps) == 1
        assert bps[0]["lines"] == [10, 20]
        assert bps[0]["object_id"] == GOOD_UUID

    async def test_multiple_set_breakpoints_accumulate(self, client):
        for line in (5, 15, 25):
            await client.set_breakpoints(
                module_type="CommonModule",
                object_id=GOOD_UUID,
                property_id=ANOTHER_UUID,
                lines=[line],
            )
        bps = await client.get_breakpoints()
        assert len(bps) == 3
        assert [bp["lines"][0] for bp in bps] == [5, 15, 25]

    async def test_cache_returns_copy_not_reference(self, client):
        await client.set_breakpoints(
            module_type="CommonModule",
            object_id=GOOD_UUID, property_id=ANOTHER_UUID, lines=[1],
        )
        bps = await client.get_breakpoints()
        bps.clear()  # mutate returned list
        # Internal cache still intact
        assert len(await client.get_breakpoints()) == 1

    async def test_set_breakpoints_with_version(self, client):
        # §6.1: version field propagates to XML body when non-empty
        await client.set_breakpoints(
            module_type="ConfigModule",
            object_id=GOOD_UUID, property_id=ANOTHER_UUID, lines=[1],
            version="1.0.42",
        )
        body = client._post.call_args.args[1]
        assert "<debugBaseData:version>1.0.42</debugBaseData:version>" in body
        cached = (await client.get_breakpoints())[0]
        assert cached["version"] == "1.0.42"

    async def test_set_breakpoints_empty_version_omits_xml(self, client):
        await client.set_breakpoints(
            module_type="CommonModule",
            object_id=GOOD_UUID, property_id=ANOTHER_UUID, lines=[1],
        )
        body = client._post.call_args.args[1]
        # Namespaced tag absent (note: XML declaration `<?xml version=...?>`
        # has substring "version" — match the full debugBaseData:version tag)
        assert "<debugBaseData:version>" not in body


@pytest.mark.asyncio
class TestGetTargetState:
    async def test_session_state_when_no_uuid(self, client):
        # Real-world finding 2026-05-09 (RDBG 8.3.27.1936): getDbgTargetState
        # без targetID отвергается с HTTP 400. Wrapper теперь возвращает
        # local session snapshot БЕЗ HTTP roundtrip.
        client._attached = True
        client._known_attached_targets.add(GOOD_UUID)
        client._stopped_targets.add(GOOD_UUID)
        client._last_stopped_target_id = GOOD_UUID

        result = await client.get_target_state(target_uuid=None)

        client._post.assert_not_awaited()  # no RDBG call
        assert result["_tag"] == "session_state"
        assert result["infobase_alias"] == "TestDB"
        assert result["session_id"] == client.session_id
        assert result["attached"] is True
        assert result["known_attached_targets"] == [GOOD_UUID]
        assert result["stopped_targets"] == [GOOD_UUID]
        assert result["last_stopped_target_id"] == GOOD_UUID

    async def test_session_state_when_disconnected(self, client):
        # Empty wrapper state — _attached=False, no targets known.
        result = await client.get_target_state(target_uuid=None)
        client._post.assert_not_awaited()
        assert result["_tag"] == "session_state"
        assert result["attached"] is False
        assert result["known_attached_targets"] == []
        assert result["stopped_targets"] == []
        assert result["last_stopped_target_id"] is None

    async def test_per_target_via_get_targets_filter(self, client):
        # When target_uuid given → filter through get_targets()
        client.get_targets = AsyncMock(return_value=[
            {"id": GOOD_UUID, "state": "StopOnNextLine", "userName": "Admin"},
            {"id": ANOTHER_UUID, "state": "Worked"},
        ])
        result = await client.get_target_state(target_uuid=GOOD_UUID)
        assert result["state"] == "StopOnNextLine"
        assert result["userName"] == "Admin"

    async def test_per_target_not_found(self, client):
        client.get_targets = AsyncMock(return_value=[
            {"id": ANOTHER_UUID, "state": "Worked"},
        ])
        result = await client.get_target_state(target_uuid=GOOD_UUID)
        assert result["_tag"] == "not_found"
        assert result["target_uuid"] == GOOD_UUID


# ---------------------------------------------------------------------------
# yukon39 post-attach handshake: initSettings → clearBreakOnNextStatement →
# setAutoAttachSettings (Debugee.attach() lines 97-109). Reviewer-flagged
# coverage gap 2026-05-10: pre-fix wrapper called cmd=initSettings with
# WRONG body (breakOnNextLine + autoAttachSettings → silent no-op), causing
# eval/step to fail post-BP-fire with HTTP 400 «UI+ - часть отладки не
# зарегистрирована». Tests lock in the correct yukon39-spec body shapes.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestInitSettingsHandshake:
    async def test_init_settings_posts_correct_cmd_and_empty_data(self, client):
        # yukon39 ServerContext.attach() sends new HTTPServerInitialDebug-
        # SettingsData() without setters → JAXB serializes empty <data/>.
        await client.init_settings()
        client._post.assert_awaited_once()
        cmd, body = client._post.await_args.args
        assert cmd == "initSettings"
        # Body must contain empty <data/> element under RDBG ns.
        assert "<debugRDBGRequestResponse:data>" in body
        assert "<debugRDBGRequestResponse:data></debugRDBGRequestResponse:data>" in body
        # Anti-regression: pre-fix broken markers MUST NOT appear.
        assert "breakOnNextLine" not in body
        assert "autoAttachSettings" not in body

    async def test_init_settings_uses_session_id(self, client):
        await client.init_settings()
        body = client._post.await_args.args[1]
        assert client.session_id in body
        assert client.infobase_alias in body


@pytest.mark.asyncio
class TestClearBreakOnNextStatement:
    async def test_clear_posts_correct_cmd(self, client):
        # yukon39 HTTPDebugClient.clearBreakOnNextStatement() lines 273-283:
        # body has only base fields (infoBaseAlias + idOfDebuggerUI), no payload.
        await client.clear_break_on_next_statement()
        client._post.assert_awaited_once()
        cmd, body = client._post.await_args.args
        assert cmd == "clearBreakOnNextStatement"
        assert client.session_id in body
        assert client.infobase_alias in body


@pytest.mark.asyncio
class TestSetAutoAttachSettings:
    async def test_default_targets_server_and_managed_client(self, client):
        await client.set_auto_attach_settings()
        cmd, body = client._post.await_args.args
        assert cmd == "setAutoAttachSettings"
        assert "<debugAutoAttach:targetType>Server</debugAutoAttach:targetType>" in body
        assert "<debugAutoAttach:targetType>ManagedClient</debugAutoAttach:targetType>" in body
        # Anti-regression: must NOT route through cmd=initSettings (pre-fix bug)
        # and must NOT include initSettings-only field breakOnNextLine.
        assert "breakOnNextLine" not in body

    async def test_custom_target_types(self, client):
        await client.set_auto_attach_settings(target_types=["BackgroundJob"])
        body = client._post.await_args.args[1]
        assert "<debugAutoAttach:targetType>BackgroundJob</debugAutoAttach:targetType>" in body
        assert "Server" not in body
        assert "ManagedClient" not in body


# ---------------------------------------------------------------------------
# §6.3 Stale Debug UI session cleanup
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestCleanupStaleSession:
    async def test_no_stale_session_no_op(self, client):
        # get_debug_id returns None — nothing to clean
        client.get_debug_id = AsyncMock(return_value=None)
        await client._cleanup_stale_session()
        # _post was never called for detach
        assert all(
            "detachDebugUI" not in (call.args[0] if call.args else "")
            for call in client._post.call_args_list
        )

    async def test_stale_session_detached(self, client):
        stale_uuid = "deadbeef-dead-beef-dead-beefdeadbeef"
        client.get_debug_id = AsyncMock(return_value=stale_uuid)
        await client._cleanup_stale_session()

        # Verify detachDebugUI was called for the stale id
        detach_calls = [
            call for call in client._post.call_args_list
            if call.args and call.args[0] == "detachDebugUI"
        ]
        assert len(detach_calls) == 1
        body = detach_calls[0].args[1]
        assert stale_uuid in body

    async def test_same_session_id_not_detached(self, client):
        # Edge case: getDebugID returns OUR session_id (we are still alive) → skip
        client.get_debug_id = AsyncMock(return_value=client.session_id)
        await client._cleanup_stale_session()
        detach_calls = [
            call for call in client._post.call_args_list
            if call.args and call.args[0] == "detachDebugUI"
        ]
        assert len(detach_calls) == 0

    async def test_zero_uuid_not_detached(self, client):
        # Real-world finding 2026-05-09: getDebugID returns "00000000-..." when
        # no stale session exists. Code must skip detach (otherwise 400 from RDBG).
        client.get_debug_id = AsyncMock(return_value=mds.ZERO_UUID)
        await client._cleanup_stale_session()
        detach_calls = [
            call for call in client._post.call_args_list
            if call.args and call.args[0] == "detachDebugUI"
        ]
        assert len(detach_calls) == 0

    async def test_get_debug_id_failure_swallowed(self, client):
        client.get_debug_id = AsyncMock(side_effect=RuntimeError("RDBG 500"))
        # Must not raise
        await client._cleanup_stale_session()

    async def test_attach_invokes_cleanup_by_default(self, client):
        client.get_debug_id = AsyncMock(return_value=None)
        # _post mock returns empty Element — attach parses "registered" by absence
        await client.attach()
        client.get_debug_id.assert_awaited_once()

    async def test_attach_skip_cleanup_when_disabled(self, client):
        client.get_debug_id = AsyncMock(return_value=None)
        await client.attach(cleanup_stale=False)
        client.get_debug_id.assert_not_called()
