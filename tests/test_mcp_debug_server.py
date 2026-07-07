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
import json
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
        await client._handle_command(
            {
                "cmdId": "targetStarted",
                "targetID": GOOD_UUID,
            }
        )
        client.attach_debug_targets.assert_awaited_once_with([GOOD_UUID])
        assert GOOD_UUID in client._known_attached_targets

    async def test_target_started_idempotent(self, client):
        client.attach_debug_targets = AsyncMock(return_value=True)
        client._known_attached_targets.add(GOOD_UUID)
        await client._handle_command(
            {
                "cmdId": "targetStarted",
                "targetID": GOOD_UUID,
            }
        )
        client.attach_debug_targets.assert_not_called()

    async def test_target_started_attach_failure_does_not_pollute_known(self, client):
        client.attach_debug_targets = AsyncMock(side_effect=RuntimeError("RDBG 400"))
        await client._handle_command(
            {
                "cmdId": "targetStarted",
                "targetID": GOOD_UUID,
            }
        )
        # Failure → target NOT added (next ping will retry)
        assert GOOD_UUID not in client._known_attached_targets

    async def test_target_started_without_target_id_noop(self, client):
        client.attach_debug_targets = AsyncMock()
        await client._handle_command({"cmdId": "targetStarted"})
        client.attach_debug_targets.assert_not_called()

    async def test_call_stack_formed_breakpoint(self, client):
        stack = [{"_tag": "frame", "line": "10"}, {"_tag": "frame", "line": "20"}]
        await client._handle_command(
            {
                "cmdId": "callStackFormed",
                "targetID": GOOD_UUID,
                "callStack": stack,
                "stopByBP": "true",
            }
        )
        assert GOOD_UUID in client._stopped_targets
        assert client._last_stopped_target_id == GOOD_UUID
        assert client._last_stack_by_target[GOOD_UUID] == stack
        assert client._stop_reason_by_target[GOOD_UUID] == "breakpoint"

    async def test_call_stack_formed_step_stop(self, client):
        await client._handle_command(
            {
                "cmdId": "callStackFormed",
                "targetID": GOOD_UUID,
                "callStack": {"_tag": "frame"},  # single-dict normalised to list
                "stopByBP": "false",
            }
        )
        assert client._stop_reason_by_target[GOOD_UUID] == "step"
        assert client._last_stack_by_target[GOOD_UUID] == [{"_tag": "frame"}]

    async def test_call_stack_formed_no_target_skipped(self, client):
        await client._handle_command(
            {
                "cmdId": "callStackFormed",
                "callStack": [],
            }
        )
        assert client._stopped_targets == set()
        assert client._last_stopped_target_id is None

    async def test_rte_processing_caches_exception(self, client):
        exc = {"_tag": "exception", "code": "42", "info": "Деление на ноль"}
        await client._handle_command(
            {
                "cmdId": "rteProcessing",
                "targetID": GOOD_UUID,
                "callStack": [{"_tag": "frame"}],
                "exception": exc,
            }
        )
        assert GOOD_UUID in client._stopped_targets
        assert client._last_stopped_target_id == GOOD_UUID
        assert client._stop_reason_by_target[GOOD_UUID] == "exception"
        assert client._last_exception_by_target[GOOD_UUID] == exc

    async def test_rte_processing_no_target_skipped(self, client):
        await client._handle_command(
            {
                "cmdId": "rteProcessing",
                "callStack": [],
            }
        )
        assert client._stopped_targets == set()
        assert client._last_exception_by_target == {}

    async def test_target_quit_clears_all_state(self, client):
        # Pre-populate state
        client._stopped_targets.add(GOOD_UUID)
        client._last_stack_by_target[GOOD_UUID] = [{"frame": 1}]
        client._stop_reason_by_target[GOOD_UUID] = "breakpoint"
        client._last_exception_by_target[GOOD_UUID] = {"code": "42"}
        client._known_attached_targets.add(GOOD_UUID)

        await client._handle_command(
            {
                "cmdId": "targetQuit",
                "targetID": GOOD_UUID,
            }
        )

        assert GOOD_UUID not in client._stopped_targets
        assert GOOD_UUID not in client._last_stack_by_target
        assert GOOD_UUID not in client._stop_reason_by_target
        assert GOOD_UUID not in client._last_exception_by_target
        assert GOOD_UUID not in client._known_attached_targets

    async def test_corrected_bp_does_not_change_state(self, client):
        await client._handle_command(
            {
                "cmdId": "correctedBP",
                "targetID": GOOD_UUID,
            }
        )
        # Just logged a warning, no state mutation
        assert client._stopped_targets == set()

    @pytest.mark.parametrize(
        "cmd_type",
        [
            "ForegroundHelperSet",
            "ForegroundHelperRequest",
            "ForegroundHelperProcess",
            "measureResultProcessing",
            "errorViewInfo",
            "rteOnBPConditionProcessing",
            "exprEvaluated",
            "valueModified",
            "unknown",
            "",
        ],
    )
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
        await client._handle_command(
            {
                "cmdIDNum": "1",  # 1 = targetStarted per DBGUIExtCmds enum
                "targetID": GOOD_UUID,
            }
        )
        client.attach_debug_targets.assert_awaited_once_with([GOOD_UUID])
        assert GOOD_UUID in client._known_attached_targets

    async def test_cmdidnum_fallback_call_stack_formed(self, client):
        await client._handle_command(
            {
                "cmdIDNum": "7",  # 7 = callStackFormed
                "targetID": GOOD_UUID,
                "callStack": [{"_tag": "frame"}],
                "stopByBP": "true",
            }
        )
        assert client._last_stopped_target_id == GOOD_UUID
        assert client._stop_reason_by_target[GOOD_UUID] == "breakpoint"

    async def test_explicit_cmdid_overrides_cmdidnum(self, client):
        # If both present, literal cmdId wins (yukon39 wire format expectation)
        client.attach_debug_targets = AsyncMock(return_value=True)
        await client._handle_command(
            {
                "cmdId": "targetStarted",
                "cmdIDNum": "999",  # bogus ordinal — must be ignored
                "targetID": GOOD_UUID,
            }
        )
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
            expression="ТекущаяДата()",
            target_uuid=GOOD_UUID,
            async_wait_timeout=0,
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
            expression="Контрагент.Ссылка",
            view_interface="context",
            async_wait_timeout=0,
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
        await client.eval_expression(
            expression="БольшаяТаблица", max_text_size=16384, async_wait_timeout=0
        )
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
        await client.eval_expression(expression="x", target_uuid=GOOD_UUID, async_wait_timeout=0)
        assert len(captured_pending) == 1, "Future must be registered before POST"

    async def test_sync_result_returns_immediately(self, client):
        # If RDBG returned the value inline (calcWaitingTime sufficed),
        # eval_expression skips the wait and returns sync_result.
        client.attach_debug_targets = AsyncMock(return_value=True)
        non_empty = ET.Element("RDBGEvalExprResponse")
        result_elem = ET.SubElement(non_empty, "result")
        ET.SubElement(result_elem, "value").text = "42"
        client._post = AsyncMock(return_value=non_empty)
        result = await client.eval_expression(
            expression="40+2", target_uuid=GOOD_UUID, async_wait_timeout=0
        )
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
            client.eval_expression(expression="x", target_uuid=GOOD_UUID, async_wait_timeout=2.0),
            eval_then_resolve(),
        )
        eval_result = results[0]
        assert eval_result, "Expected non-empty result delivered via event"
        assert eval_result[0]["value"] == "result-payload"
        assert len(client._pending_evals) == 0

    async def test_unknown_result_id_event_is_ignored(self, client):
        # exprEvaluated for a result_id that has no pending future just logs
        # a debug message — must not raise or pollute state.
        await client._handle_command(
            {
                "cmdId": "exprEvaluated",
                "evalExprResBaseData": {"expressionResultID": GOOD_UUID, "value": "ghost"},
            }
        )
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
            400,
            content="UI+ - часть отладки не зарегистрирована".encode("utf-8"),
            request=_httpx.Request("POST", "http://test/"),
        )
        ok_resp = _httpx.Response(
            200,
            content=b"<root/>",
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
            400,
            content="UI+ - часть отладки не зарегистрирована".encode("utf-8"),
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
            400,
            content=b"<error>Some other error</error>",
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
            400,
            content="UI+ - часть отладки не зарегистрирована".encode("utf-8"),
            request=_httpx.Request("POST", "http://test/"),
        )
        attach_ok = _httpx.Response(
            200,
            content=b"<root><result>registered</result></root>",
            request=_httpx.Request("POST", "http://test/"),
        )
        ok_resp = _httpx.Response(
            200,
            content=b"<root/>",
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
        client._http.post = AsyncMock(
            side_effect=[
                ui_plus_400,
                ok_resp,
                ok_resp,
                ui_plus_400,
                ok_resp,
                attach_ok,
                ok_resp,
                ok_resp,
                ok_resp,
                ok_resp,
            ]
        )

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
            400,
            content="UI+ - часть отладки не зарегистрирована".encode("utf-8"),
            request=_httpx.Request("POST", "http://test/"),
        )
        attach_ok = _httpx.Response(
            200,
            content=b"<root><result>registered</result></root>",
            request=_httpx.Request("POST", "http://test/"),
        )
        ok_resp = _httpx.Response(
            200,
            content=b"<root/>",
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
        client._http.post = AsyncMock(
            side_effect=[
                ui_plus_400,
                ui_plus_400,
                ok_resp,
                attach_ok,
                ok_resp,
                ok_resp,
                ok_resp,
                ok_resp,
            ]
        )

        old_session_id = client.session_id
        await client.set_break_on_next_statement()
        assert client._http.post.await_count == 8
        assert client.session_id != old_session_id

    async def test_escalation_url_includes_attachDebugUI(self, client):
        # Verify the 6th call (after light handshake fail) uses attachDebugUI.
        import httpx as _httpx

        await self._restore_real_post(client)

        ui_plus_400 = _httpx.Response(
            400,
            content="UI+ - часть отладки не зарегистрирована".encode("utf-8"),
            request=_httpx.Request("POST", "http://test/"),
        )
        attach_ok = _httpx.Response(
            200,
            content=b"<root><result>registered</result></root>",
            request=_httpx.Request("POST", "http://test/"),
        )
        ok_resp = _httpx.Response(
            200,
            content=b"<root/>",
            request=_httpx.Request("POST", "http://test/"),
        )

        client._http = MagicMock()
        client._http.post = AsyncMock(
            side_effect=[
                ui_plus_400,
                ok_resp,
                ok_resp,
                ui_plus_400,
                ok_resp,
                attach_ok,
                ok_resp,
                ok_resp,
                ok_resp,
                ok_resp,
            ]
        )
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
        # Fix #5 (2026-05-10): cache consolidates multiple set calls на one
        # (module, property) tuple в один entry с merged lines, чтобы каждый
        # submit отправлял FULL workspace (RDBG setBreakpoints REPLACES
        # workspace per-call). Pre-fix expectation было «3 separate entries» —
        # post-fix correct expectation: 1 entry с 3 lines.
        for line in (5, 15, 25):
            await client.set_breakpoints(
                module_type="CommonModule",
                object_id=GOOD_UUID,
                property_id=ANOTHER_UUID,
                lines=[line],
            )
        bps = await client.get_breakpoints()
        assert len(bps) == 1
        assert sorted(bps[0]["lines"]) == [5, 15, 25]

    async def test_cache_returns_copy_not_reference(self, client):
        await client.set_breakpoints(
            module_type="CommonModule",
            object_id=GOOD_UUID,
            property_id=ANOTHER_UUID,
            lines=[1],
        )
        bps = await client.get_breakpoints()
        bps.clear()  # mutate returned list
        # Internal cache still intact
        assert len(await client.get_breakpoints()) == 1

    async def test_set_breakpoints_with_version(self, client):
        # §6.1: version field propagates to XML body when non-empty
        await client.set_breakpoints(
            module_type="ConfigModule",
            object_id=GOOD_UUID,
            property_id=ANOTHER_UUID,
            lines=[1],
            version="1.0.42",
        )
        body = client._post.call_args.args[1]
        assert "<debugBaseData:version>1.0.42</debugBaseData:version>" in body
        cached = (await client.get_breakpoints())[0]
        assert cached["version"] == "1.0.42"

    async def test_set_breakpoints_empty_version_omits_xml(self, client):
        await client.set_breakpoints(
            module_type="CommonModule",
            object_id=GOOD_UUID,
            property_id=ANOTHER_UUID,
            lines=[1],
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
        client.get_targets = AsyncMock(
            return_value=[
                {"id": GOOD_UUID, "state": "StopOnNextLine", "userName": "Admin"},
                {"id": ANOTHER_UUID, "state": "Worked"},
            ]
        )
        result = await client.get_target_state(target_uuid=GOOD_UUID)
        assert result["state"] == "StopOnNextLine"
        assert result["userName"] == "Admin"

    async def test_per_target_not_found(self, client):
        client.get_targets = AsyncMock(
            return_value=[
                {"id": ANOTHER_UUID, "state": "Worked"},
            ]
        )
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
    async def test_default_targets_expanded_after_p0_5(self, client):
        # Roadmap 260511 §P0.5 (2026-05-11): расширенный filter после yukon39
        # XSD review. debugAutoAttach.xsd подтверждает DebugTargetType enum
        # включает HTTPService/WEBService/JOB/JobFileMode/COMConnector/OData.
        # Previous ROLLBACK ошибочно считал их invalid → BPs не fire на JOB
        # rphost (1c-mcp-crud execute_code spawn'ит как JOB).
        await client.set_auto_attach_settings()
        cmd, body = client._post.await_args.args
        assert cmd == "setAutoAttachSettings"
        # Must include all 8 default types from P0.5 expansion
        for t in (
            "Server",
            "ManagedClient",
            "HTTPService",
            "WEBService",
            "JOB",
            "JobFileMode",
            "COMConnector",
            "OData",
        ):
            assert f"<debugAutoAttach:targetType>{t}</debugAutoAttach:targetType>" in body, (
                f"Missing targetType: {t}"
            )
        # Anti-regression: must NOT route через cmd=initSettings (pre-fix bug)
        assert "breakOnNextLine" not in body

    async def test_custom_target_types(self, client):
        await client.set_auto_attach_settings(target_types=["BackgroundJob"])
        body = client._post.await_args.args[1]
        assert "<debugAutoAttach:targetType>BackgroundJob</debugAutoAttach:targetType>" in body
        assert "Server" not in body
        assert "ManagedClient" not in body


@pytest.mark.asyncio
class TestReapplyBPWorkspace:
    """Roadmap 260511 §P0.5: re-apply BPs on targetStarted to cover
    short-lived JOB targets (1c-mcp-crud:execute_code)."""

    async def test_noop_when_cache_empty(self, client):
        # No BPs cached → no setBreakpoints call
        post_count_before = client._post.await_count
        await client._reapply_bp_workspace()
        assert client._post.await_count == post_count_before

    async def test_replays_cached_bps_as_single_setbreakpoints(self, client):
        # Seed cache with 2 BP entries (different modules)
        client._set_breakpoints_cache = [
            {
                "module_type": "ManagerModule",
                "object_id": "obj-1",
                "property_id": "prop-1",
                "lines": [80],
                "ext_id": 0,
                "url": "",
                "extension_name": "",
                "version": "",
            },
            {
                "module_type": "CommonModule",
                "object_id": "obj-2",
                "property_id": "prop-2",
                "lines": [10, 20],
                "ext_id": 0,
                "url": "",
                "extension_name": "",
                "version": "",
            },
        ]
        await client._reapply_bp_workspace()
        cmd, body = client._post.await_args.args
        assert cmd == "setBreakpoints"
        # Both module groups + all lines в одном request body
        assert "<debugBaseData:objectID>obj-1</debugBaseData:objectID>" in body
        assert "<debugBaseData:objectID>obj-2</debugBaseData:objectID>" in body
        assert "<debugBreakpoints:line>80</debugBreakpoints:line>" in body
        assert "<debugBreakpoints:line>10</debugBreakpoints:line>" in body
        assert "<debugBreakpoints:line>20</debugBreakpoints:line>" in body
        # Single bpWorkspace wrapper (replace semantics)
        assert body.count("<debugRDBGRequestResponse:bpWorkspace>") == 1


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
            call
            for call in client._post.call_args_list
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
            call
            for call in client._post.call_args_list
            if call.args and call.args[0] == "detachDebugUI"
        ]
        assert len(detach_calls) == 0

    async def test_zero_uuid_not_detached(self, client):
        # Real-world finding 2026-05-09: getDebugID returns "00000000-..." when
        # no stale session exists. Code must skip detach (otherwise 400 from RDBG).
        client.get_debug_id = AsyncMock(return_value=mds.ZERO_UUID)
        await client._cleanup_stale_session()
        detach_calls = [
            call
            for call in client._post.call_args_list
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


# ---------------------------------------------------------------------------
# §12.7 — cluster_load probe + session_diff + scenario validation
# ---------------------------------------------------------------------------


class TestStaleDetection:
    """Fix A+D §12.9 — wrapper file mtime vs MCP startup timestamp."""

    def test_no_stale_when_file_unchanged(self, monkeypatch):
        # mtime <= _MODULE_LOADED_AT → no warning
        import os

        monkeypatch.setattr(os.path, "getmtime", lambda p: mds._MODULE_LOADED_AT - 100)
        assert mds._get_stale_hint() is None

    def test_stale_detected_when_file_newer(self, monkeypatch):
        import os

        # Симулируем что файл был изменён ПОСЛЕ MCP startup
        monkeypatch.setattr(os.path, "getmtime", lambda p: mds._MODULE_LOADED_AT + 60)
        hint = mds._get_stale_hint()
        assert hint is not None
        assert "/mcp reconnect" in hint
        assert "60s" in hint

    def test_oserror_returns_none_safe(self, monkeypatch):
        import os

        def _boom(p):
            raise OSError("file gone")

        monkeypatch.setattr(os.path, "getmtime", _boom)
        # Не raise, не блокирует — graceful None
        assert mds._get_stale_hint() is None


@pytest.mark.asyncio
class TestStaleHintInResponses:
    """Fix D §12.9 — _stale_hint propagates в MCP tool responses."""

    async def test_health_check_no_stale_hint_when_fresh(self, monkeypatch):
        monkeypatch.setattr(mds, "_get_stale_hint", lambda: None)
        monkeypatch.setattr(mds, "_hc_collect_checks", lambda c: {})
        mds._client = None
        raw = await mds.debug_health_check()
        result = json.loads(raw)
        assert "stale_warning" not in result

    async def test_health_check_includes_stale_warning(self, monkeypatch):
        monkeypatch.setattr(mds, "_get_stale_hint", lambda: "Wrapper modified — reconnect please")
        monkeypatch.setattr(mds, "_hc_collect_checks", lambda c: {})
        mds._client = None
        raw = await mds.debug_health_check()
        result = json.loads(raw)
        assert result["stale_warning"] == "Wrapper modified — reconnect please"

    async def test_session_summary_includes_stale_hint(self, monkeypatch):
        monkeypatch.setattr(mds, "_get_stale_hint", lambda: "stale-msg")
        from mcp_debug_server import RDBGClient

        c = RDBGClient(debug_url="http://test", infobase_alias="X")
        mds._client = c
        raw = await mds.debug_session_summary()
        result = json.loads(raw)
        assert result["_stale_hint"] == "stale-msg"

    async def test_session_diff_includes_stale_hint(self, monkeypatch):
        monkeypatch.setattr(mds, "_get_stale_hint", lambda: "stale-msg")
        prev = {
            "session_id": "p1",
            "breakpoints": {},
            "evaluations": {},
            "ui_plus_retries": 0,
            "stop_events": [],
        }
        curr = {
            "session_id": "c1",
            "breakpoints": {},
            "evaluations": {},
            "ui_plus_retries": 0,
            "stop_events": [],
        }
        store = {"p1": prev, "c1": curr}
        monkeypatch.setattr(mds, "_load_session_summary", lambda sid: store.get(sid))
        raw = await mds.debug_session_diff(prev_session_id="p1", curr_session_id="c1")
        result = json.loads(raw)
        assert result["_stale_hint"] == "stale-msg"


class TestClusterLoadProbe:
    """L1 §12.7 — warn если rphost connections > threshold."""

    def test_no_rac_returns_warn_skip(self, monkeypatch):
        monkeypatch.setattr(mds, "_find_rac_exe", lambda: None)
        result = mds._hc_probe_cluster_load()
        assert result["status"] == "warn"
        assert "rac.exe not found" in result["detail"]

    def test_low_load_returns_pass(self, monkeypatch):
        monkeypatch.setattr(mds, "_find_rac_exe", lambda: "/fake/rac")
        monkeypatch.setattr(mds, "_rac_get_cluster_uuid", lambda *a: "cuuid")
        fake = MagicMock(
            returncode=0,
            stdout=(
                "process : aaa\npid : 100\nconnections : 3\n"
                "process : bbb\npid : 200\nconnections : 5\n"
            ),
        )
        monkeypatch.setattr(mds.subprocess, "run", lambda *a, **kw: fake)
        monkeypatch.delenv("BSL_DEBUG_CONN_THRESHOLD", raising=False)
        result = mds._hc_probe_cluster_load()
        assert result["status"] == "pass"
        assert "≤10" in result["detail"]

    def test_high_load_returns_warn_with_pids(self, monkeypatch):
        monkeypatch.setattr(mds, "_find_rac_exe", lambda: "/fake/rac")
        monkeypatch.setattr(mds, "_rac_get_cluster_uuid", lambda *a: "cuuid")
        fake = MagicMock(
            returncode=0,
            stdout=(
                "process : aaa\npid : 100\nconnections : 25\n"
                "process : bbb\npid : 200\nconnections : 3\n"
            ),
        )
        monkeypatch.setattr(mds.subprocess, "run", lambda *a, **kw: fake)
        result = mds._hc_probe_cluster_load()
        assert result["status"] == "warn"
        assert "high-load" in result["detail"]
        assert "100" in result["detail"] and "25" in result["detail"]
        assert "fix" in result

    def test_threshold_via_env_var(self, monkeypatch):
        monkeypatch.setattr(mds, "_find_rac_exe", lambda: "/fake/rac")
        monkeypatch.setattr(mds, "_rac_get_cluster_uuid", lambda *a: "cuuid")
        fake = MagicMock(returncode=0, stdout=("process : aaa\npid : 100\nconnections : 5\n"))
        monkeypatch.setattr(mds.subprocess, "run", lambda *a, **kw: fake)
        monkeypatch.setenv("BSL_DEBUG_CONN_THRESHOLD", "3")  # threshold ниже 5
        result = mds._hc_probe_cluster_load()
        assert result["status"] == "warn"


@pytest.mark.asyncio
class TestSessionDiff:
    """L3 §12.7 — cross-session diff для regression detection."""

    def _summary(
        self, sid: str, fired: int, evals: int = 0, failures: int = 0, ui_retries: int = 0
    ) -> dict:
        return {
            "session_id": sid,
            "started_at": "2026-05-10T10:00:00",
            "infobase_alias": "X",
            "breakpoints": {
                "set_count": 3,
                "fire_count": fired,
                "by_location": {},
                "fire_rate": fired / 3,
            },
            "evaluations": {"count": evals, "failures": failures, "errors": []},
            "ui_plus_retries": ui_retries,
            "recycle": {"force_invoked": False, "method_used": None},
            "stop_events": [{"ts": "t1"}] * fired,
            "rphosts_seen": [],
            "attached": False,
        }

    def test_diff_summaries_no_regression(self):
        prev = self._summary("p1", fired=3, evals=5)
        curr = self._summary("c1", fired=3, evals=5)
        diff = mds._diff_summaries(prev, curr)
        assert diff["verdict"] == "NO_REGRESSION"
        assert diff["regression_indicators"] == []
        assert diff["deltas"]["bp_fire_count"] == 0

    def test_diff_summaries_detects_bp_regression(self):
        prev = self._summary("p1", fired=3, evals=5)
        curr = self._summary("c1", fired=2, evals=5)  # 1 BP перестал fire
        diff = mds._diff_summaries(prev, curr)
        assert diff["verdict"] == "REGRESSION"
        assert diff["deltas"]["bp_fire_count"] == -1
        assert any("regressed" in i for i in diff["regression_indicators"])

    def test_diff_summaries_detects_eval_failures(self):
        prev = self._summary("p1", fired=3, evals=5, failures=0)
        curr = self._summary("c1", fired=3, evals=5, failures=2)
        diff = mds._diff_summaries(prev, curr)
        assert diff["verdict"] == "REGRESSION"
        assert any("eval failures" in i for i in diff["regression_indicators"])

    def test_diff_summaries_detects_ui_plus_retries_increase(self):
        prev = self._summary("p1", fired=3, ui_retries=0)
        curr = self._summary("c1", fired=3, ui_retries=4)
        diff = mds._diff_summaries(prev, curr)
        assert diff["verdict"] == "REGRESSION"
        assert any("UI+ retries" in i for i in diff["regression_indicators"])

    async def test_session_diff_tool_handles_missing_prev(self, monkeypatch):
        monkeypatch.setattr(mds, "_load_session_summary", lambda sid: None)
        raw = await mds.debug_session_diff(prev_session_id="nonexistent")
        result = json.loads(raw)
        assert result["status"] == "error"
        assert "not found" in result["error"]

    async def test_session_diff_tool_compares_two_loaded(self, monkeypatch):
        prev = self._summary("p1", fired=3)
        curr = self._summary("c1", fired=2)
        store = {"p1": prev, "c1": curr}
        monkeypatch.setattr(mds, "_load_session_summary", lambda sid: store.get(sid))
        raw = await mds.debug_session_diff(prev_session_id="p1", curr_session_id="c1")
        result = json.loads(raw)
        assert result["verdict"] == "REGRESSION"
        assert result["prev_session"] == "p1"
        assert result["curr_session"] == "c1"


# ---------------------------------------------------------------------------
# §12 Level 1 — debug_health_check probes + tool
# ---------------------------------------------------------------------------


class TestHealthCheckProbes:
    """Pure probe helpers — mocked subprocess + socket layers."""

    def test_dbgs_port_probe_pass_when_listening(self, monkeypatch):
        # Mock socket.connect → success (no exception)
        import socket

        captured = {}

        class FakeSocket:
            def __init__(self, family, type_):
                captured["init"] = True

            def settimeout(self, t):
                pass

            def connect(self, addr):
                captured["addr"] = addr

            def close(self):
                pass

        monkeypatch.setattr(socket, "socket", FakeSocket)
        result = mds._hc_probe_dbgs_port("localhost", 1550)
        assert result["status"] == "pass"
        assert "1550" in result["detail"]

    def test_dbgs_port_probe_fail_on_refused(self, monkeypatch):
        import socket

        class FakeSocket:
            def __init__(self, *a):
                pass

            def settimeout(self, t):
                pass

            def connect(self, addr):
                raise ConnectionRefusedError("nope")

            def close(self):
                pass

        monkeypatch.setattr(socket, "socket", FakeSocket)
        result = mds._hc_probe_dbgs_port()
        assert result["status"] == "fail"
        assert "fix" in result

    def test_ragent_debug_flag_pass_when_both_present(self, monkeypatch):
        monkeypatch.setattr(mds.sys, "platform", "win32")
        fake = MagicMock(
            returncode=0,
            stdout='"path\\to\\ragent.exe" -srvc -agent -debug -http -d "..."',
            stderr="",
        )
        monkeypatch.setattr(mds.subprocess, "run", lambda *a, **kw: fake)
        result = mds._hc_probe_ragent_debug_flag()
        assert result["status"] == "pass"

    def test_ragent_debug_flag_fail_when_missing(self, monkeypatch):
        monkeypatch.setattr(mds.sys, "platform", "win32")
        fake = MagicMock(returncode=0, stdout='"path\\to\\ragent.exe" -srvc -agent', stderr="")
        monkeypatch.setattr(mds.subprocess, "run", lambda *a, **kw: fake)
        result = mds._hc_probe_ragent_debug_flag()
        assert result["status"] == "fail"
        assert "missing flags" in result["detail"]
        assert "fix" in result

    def test_ragent_debug_flag_skip_on_non_windows(self, monkeypatch):
        monkeypatch.setattr(mds.sys, "platform", "linux")
        result = mds._hc_probe_ragent_debug_flag()
        assert result["status"] == "warn"

    def test_rphost_baseline_pass_when_empty(self, monkeypatch):
        monkeypatch.setattr(mds, "detect_pre_existing_rphosts", lambda: [])
        result = mds._hc_probe_rphost_baseline()
        assert result["status"] == "pass"

    def test_rphost_baseline_warn_when_pre_existing(self, monkeypatch):
        monkeypatch.setattr(
            mds,
            "detect_pre_existing_rphosts",
            lambda: [{"pid": 100, "name": "rphost.exe"}, {"pid": 200, "name": "rphost.exe"}],
        )
        result = mds._hc_probe_rphost_baseline()
        assert result["status"] == "warn"
        assert "100" in result["detail"] and "200" in result["detail"]
        assert result["fix"] == "kill-stale-rphosts (auto-prepare action)"

    def test_rac_available_pass_with_cluster(self, monkeypatch):
        monkeypatch.setattr(mds, "_find_rac_exe", lambda: "C:/fake/rac.exe")
        monkeypatch.setattr(
            mds, "_rac_get_cluster_uuid", lambda *a: "11111111-2222-3333-4444-555555555555"
        )
        result = mds._hc_probe_rac_available()
        assert result["status"] == "pass"
        assert "11111111" in result["detail"]

    def test_rac_available_warn_when_missing(self, monkeypatch):
        monkeypatch.setattr(mds, "_find_rac_exe", lambda: None)
        result = mds._hc_probe_rac_available()
        assert result["status"] == "warn"

    def test_env_vars_reports_extras(self, monkeypatch):
        monkeypatch.setenv("RAC_CLUSTER_USER", "Admin")
        monkeypatch.delenv("RAC_CLUSTER_PWD", raising=False)
        monkeypatch.setenv("BSL_DEBUG_ALLOW_SERVICE_RESTART", "true")
        result = mds._hc_probe_env_vars()
        assert result["status"] == "pass"
        assert result["_extras"]["RAC_CLUSTER_USER"] is True
        assert result["_extras"]["RAC_CLUSTER_PWD"] is False
        assert result["_extras"]["BSL_DEBUG_ALLOW_SERVICE_RESTART"] is True

    def test_sddl_au_grant_pass_when_present(self, monkeypatch):
        monkeypatch.setattr(mds.sys, "platform", "win32")
        fake = MagicMock(returncode=0, stdout="D:(A;;LCSWRPWPCR;;;AU)(A;;CCDC;;;BA)", stderr="")
        monkeypatch.setattr(mds.subprocess, "run", lambda *a, **kw: fake)
        result = mds._hc_probe_sddl_au_grant()
        assert result["status"] == "pass"

    def test_sddl_au_grant_warn_without_au(self, monkeypatch):
        monkeypatch.setattr(mds.sys, "platform", "win32")
        fake = MagicMock(returncode=0, stdout="D:(A;;CCDC;;;BA)(A;;CCDC;;;SY)", stderr="")
        monkeypatch.setattr(mds.subprocess, "run", lambda *a, **kw: fake)
        result = mds._hc_probe_sddl_au_grant()
        assert result["status"] == "warn"
        assert "fix" in result

    def test_active_session_pass_when_no_client(self):
        result = mds._hc_probe_active_session(None)
        assert result["status"] == "pass"
        assert "no active" in result["detail"]


class TestHealthCheckRecommendation:
    """Workflow recommender — picks path based on probe results."""

    def test_read_only_when_dbgs_down(self):
        checks = {"dbgs_port_1550": {"status": "fail"}}
        assert mds._hc_recommend_workflow(checks) == "read-only"

    def test_thin_client_when_no_pre_existing(self):
        checks = {
            "dbgs_port_1550": {"status": "pass"},
            "rphost_count_baseline": {"status": "pass"},
            "rac_exe_path": {"status": "pass"},
        }
        assert mds._hc_recommend_workflow(checks) == "thin-client"

    def test_force_recycle_when_rphost_warn_rac_ok(self):
        checks = {
            "dbgs_port_1550": {"status": "pass"},
            "rphost_count_baseline": {"status": "warn"},
            "rac_exe_path": {"status": "pass"},
        }
        assert mds._hc_recommend_workflow(checks) == "force-recycle"

    def test_service_restart_when_rphost_warn_rac_missing_svc_ok(self):
        checks = {
            "dbgs_port_1550": {"status": "pass"},
            "rphost_count_baseline": {"status": "warn"},
            "rac_exe_path": {"status": "warn"},
            "env_vars": {"_extras": {"BSL_DEBUG_ALLOW_SERVICE_RESTART": True}},
            "sddl_au_grant": {"status": "pass"},
        }
        assert mds._hc_recommend_workflow(checks) == "service-restart"


@pytest.mark.asyncio
class TestDebugHealthCheckTool:
    """End-to-end health_check MCP tool."""

    async def test_probe_mode_returns_structured_json(self, monkeypatch):
        # Mock all probes to known-good
        monkeypatch.setattr(
            mds,
            "_hc_collect_checks",
            lambda c: {
                "dbgs_port_1550": {"status": "pass", "detail": "ok"},
                "rphost_count_baseline": {"status": "pass", "detail": "no rphost"},
                "env_vars": {"_extras": {"BSL_DEBUG_ALLOW_SERVICE_RESTART": False}},
            },
        )
        mds._client = None
        raw = await mds.debug_health_check()
        result = json.loads(raw)
        assert result["ready"] is True
        assert result["mode"] == "probe"
        assert "checks" in result
        assert "elapsed_ms" in result
        assert "recommended_workflow" in result

    async def test_prepare_mode_requires_actions(self, monkeypatch):
        monkeypatch.setattr(mds, "_hc_collect_checks", lambda c: {})
        mds._client = None
        raw = await mds.debug_health_check(mode="prepare")
        result = json.loads(raw)
        assert result["status"] == "error"
        assert "actions" in result["error"]

    async def test_prepare_rejects_non_whitelisted_actions(self, monkeypatch):
        monkeypatch.setattr(mds, "_hc_collect_checks", lambda c: {})
        mds._client = None
        raw = await mds.debug_health_check(mode="prepare", actions=["modify-sddl"])
        result = json.loads(raw)
        # action rejected, not in whitelist
        assert any("rejected" in a.get("result", "") for a in result["actions_executed"])

    async def test_prepare_kill_stale_calls_recycle(self, monkeypatch):
        monkeypatch.setattr(mds, "_hc_collect_checks", lambda c: {})
        monkeypatch.setattr(
            mds, "detect_pre_existing_rphosts", lambda: [{"pid": 999, "name": "rphost.exe"}]
        )
        called = []
        monkeypatch.setattr(
            mds,
            "force_recycle_rphost_processes",
            lambda pids: (
                called.append(pids) or {"killed": pids, "failed": [], "method": "rac.turn_off"}
            ),
        )
        mds._client = None
        raw = await mds.debug_health_check(mode="prepare", actions=["kill-stale-rphosts"])
        result = json.loads(raw)
        assert called == [[999]]
        assert result["actions_executed"][0]["action"] == "kill-stale-rphosts"


# ---------------------------------------------------------------------------
# §12.3 Level 3 — debug_session_summary metrics
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestSessionSummary:
    """Session metrics tracking + summary tool."""

    async def test_no_session_returns_marker(self, monkeypatch):
        mds._client = None
        raw = await mds.debug_session_summary()
        result = json.loads(raw)
        assert result["status"] == "no_session"

    async def test_summary_returns_structure(self, monkeypatch):
        from mcp_debug_server import RDBGClient

        c = RDBGClient(debug_url="http://test", infobase_alias="X")
        mds._client = c
        raw = await mds.debug_session_summary()
        result = json.loads(raw)
        assert "session_id" in result
        assert "started_at" in result
        assert result["infobase_alias"] == "X"
        assert result["breakpoints"]["set_count"] == 0
        assert result["breakpoints"]["fire_count"] == 0
        assert result["evaluations"]["count"] == 0
        assert result["ui_plus_retries"] == 0
        assert result["recycle"]["force_invoked"] is False

    async def test_summary_counts_set_breakpoints(self, monkeypatch):
        from mcp_debug_server import RDBGClient

        c = RDBGClient(debug_url="http://test", infobase_alias="X")

        async def _fake_post(cmd, body, **kw):
            return ET.Element("empty")

        monkeypatch.setattr(c, "_post", _fake_post)
        await c.set_breakpoints("ConfigModule", "obj1", "prop1", [10, 20])
        await c.set_breakpoints("ConfigModule", "obj2", "prop2", [30])
        mds._client = c
        raw = await mds.debug_session_summary()
        result = json.loads(raw)
        # 3 lines total across consolidated cache
        assert result["breakpoints"]["set_count"] == 3

    async def test_markdown_format_renders(self, monkeypatch):
        from mcp_debug_server import RDBGClient

        c = RDBGClient(debug_url="http://test", infobase_alias="X")
        mds._client = c
        raw = await mds.debug_session_summary(format="markdown")
        assert raw.startswith("## Debug Session")
        assert "Infobase: **X**" in raw
        assert "BPs:" in raw
        assert "UI+ retries:" in raw

    async def test_eval_count_increments(self, monkeypatch):
        from mcp_debug_server import RDBGClient

        c = RDBGClient(debug_url="http://test", infobase_alias="X")
        c._stopped_targets.add("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        c._last_stopped_target_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        c._known_attached_targets.add("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")

        async def _fake_post(cmd, body, **kw):
            # Return immediately с inline result чтобы eval не висел в await
            root = ET.Element("response")
            child = ET.SubElement(root, "evalExprResBaseData")
            child.text = "result"
            return root

        monkeypatch.setattr(c, "_post", _fake_post)
        await c.eval_expression("1+1", async_wait_timeout=0)
        await c.eval_expression("2+2", async_wait_timeout=0)
        assert c._eval_count == 2


# ---------------------------------------------------------------------------
# Fix #5 (live finding 2026-05-10) — BP aggregation across modules
# ---------------------------------------------------------------------------


class TestAggregateBreakpoints:
    """Pure helper: merge cached BPs + new entry into per-module groups."""

    def _entry(self, oid, pid, lines, mt="ConfigModule"):
        return {
            "module_type": mt,
            "object_id": oid,
            "property_id": pid,
            "lines": list(lines),
            "ext_id": 0,
            "url": "",
            "extension_name": "",
            "version": "",
        }

    def test_empty_cache_single_entry(self):
        new = self._entry("obj1", "prop1", [10, 20])
        groups = mds._aggregate_breakpoints([], new)
        assert len(groups) == 1
        key = ("ConfigModule", "obj1", "prop1", 0, "", "", "")
        assert groups[key] == {10: "", 20: ""}

    def test_two_lines_same_module_dedupe(self):
        cache = [self._entry("objA", "propA", [10])]
        new = self._entry("objA", "propA", [20])
        groups = mds._aggregate_breakpoints(cache, new)
        # Same module → consolidated into single key with 2 lines
        assert len(groups) == 1
        assert list(groups.values())[0] == {10: "", 20: ""}

    def test_duplicate_lines_dedupe_to_one(self):
        cache = [self._entry("objA", "propA", [42])]
        new = self._entry("objA", "propA", [42])
        groups = mds._aggregate_breakpoints(cache, new)
        assert list(groups.values())[0] == {42: ""}

    def test_different_modules_keep_separate(self):
        cache = [self._entry("objA", "propA", [10])]
        new = self._entry("objB", "propB", [20])
        groups = mds._aggregate_breakpoints(cache, new)
        assert len(groups) == 2

    def test_different_property_keep_separate(self):
        cache = [self._entry("objA", "propObj", [10])]
        new = self._entry("objA", "propMan", [20])
        groups = mds._aggregate_breakpoints(cache, new)
        assert len(groups) == 2

    def test_lines_sorted_in_output(self):
        cache = [self._entry("objA", "propA", [50, 10])]
        new = self._entry("objA", "propA", [30])
        groups = mds._aggregate_breakpoints(cache, new)
        assert list(groups.values())[0] == {10: "", 30: "", 50: ""}


@pytest.mark.asyncio
class TestSetBreakpointsAggregation:
    """End-to-end: set_breakpoints submits full workspace + reconciles cache."""

    @pytest.fixture
    def client_mock_post(self, monkeypatch):
        from mcp_debug_server import RDBGClient

        c = RDBGClient(debug_url="http://test", infobase_alias="X")
        captured = []

        async def _fake_post(cmd, body, **kwargs):
            captured.append((cmd, body))
            return ET.Element("empty")

        monkeypatch.setattr(c, "_post", _fake_post)
        return c, captured

    async def test_two_lines_same_module_in_one_workspace(self, client_mock_post):
        c, captured = client_mock_post
        await c.set_breakpoints("ConfigModule", "obj1", "prop1", [10])
        await c.set_breakpoints("ConfigModule", "obj1", "prop1", [20])
        last_body = captured[-1][1]
        assert "<debugBreakpoints:line>10</debugBreakpoints:line>" in last_body
        assert "<debugBreakpoints:line>20</debugBreakpoints:line>" in last_body
        assert last_body.count("<debugBreakpoints:moduleBPInfo>") == 1

    async def test_two_modules_produce_two_module_bp_infos(self, client_mock_post):
        c, captured = client_mock_post
        await c.set_breakpoints("ConfigModule", "obj1", "prop1", [10])
        await c.set_breakpoints("ConfigModule", "obj2", "prop2", [20])
        last_body = captured[-1][1]
        assert last_body.count("<debugBreakpoints:moduleBPInfo>") == 2
        assert "obj1" in last_body and "obj2" in last_body

    async def test_cache_reconciled_after_submit(self, client_mock_post):
        c, _ = client_mock_post
        await c.set_breakpoints("ConfigModule", "obj1", "prop1", [10])
        await c.set_breakpoints("ConfigModule", "obj1", "prop1", [20])
        assert len(c._set_breakpoints_cache) == 1
        assert sorted(c._set_breakpoints_cache[0]["lines"]) == [10, 20]

    async def test_three_bps_two_modules_full_workspace(self, client_mock_post):
        c, captured = client_mock_post
        # Mirror live test 2026-05-10 что вскрыл Fix #5
        await c.set_breakpoints("ConfigModule", "obj-doc", "prop-obj", [141])
        await c.set_breakpoints("ConfigModule", "obj-doc", "prop-obj", [145])
        await c.set_breakpoints("ConfigModule", "obj-cm", "prop-cm", [208])
        last_body = captured[-1][1]
        for L in (141, 145, 208):
            assert f"<debugBreakpoints:line>{L}</debugBreakpoints:line>" in last_body
        assert last_body.count("<debugBreakpoints:moduleBPInfo>") == 2
        assert len(c._set_breakpoints_cache) == 2


# ---------------------------------------------------------------------------
# §11 Roadmap Solutions A/B — pre-existing rphost detection + force-recycle
# ---------------------------------------------------------------------------


class TestDetectPreExistingRphosts:
    """Solution B preflight detection (module-level helper, no client)."""

    def test_non_windows_returns_empty(self, monkeypatch):
        # Detection is Windows-only by design (taskkill / tasklist tooling)
        monkeypatch.setattr(mds.sys, "platform", "linux")
        assert mds.detect_pre_existing_rphosts() == []

    def test_subprocess_failure_returns_empty(self, monkeypatch):
        monkeypatch.setattr(mds.sys, "platform", "win32")

        def _boom(*args, **kwargs):
            raise FileNotFoundError("tasklist.exe not on PATH")

        monkeypatch.setattr(mds.subprocess, "run", _boom)
        assert mds.detect_pre_existing_rphosts() == []

    def test_no_rphosts_running_returns_empty(self, monkeypatch):
        monkeypatch.setattr(mds.sys, "platform", "win32")
        fake = MagicMock()
        fake.returncode = 0
        fake.stdout = "INFO: No tasks are running which match the specified criteria."
        monkeypatch.setattr(mds.subprocess, "run", lambda *a, **kw: fake)
        assert mds.detect_pre_existing_rphosts() == []

    def test_parses_csv_with_pids(self, monkeypatch):
        monkeypatch.setattr(mds.sys, "platform", "win32")
        fake = MagicMock()
        fake.returncode = 0
        # tasklist /FO CSV /NH format: "name","pid","session","#","mem"
        fake.stdout = (
            '"rphost.exe","12345","Services","0","123 K"\n'
            '"rphost.exe","67890","Services","0","456 K"\n'
        )
        monkeypatch.setattr(mds.subprocess, "run", lambda *a, **kw: fake)
        rphosts = mds.detect_pre_existing_rphosts()
        assert rphosts == [
            {"pid": 12345, "name": "rphost.exe"},
            {"pid": 67890, "name": "rphost.exe"},
        ]

    def test_skips_malformed_pid(self, monkeypatch):
        monkeypatch.setattr(mds.sys, "platform", "win32")
        fake = MagicMock()
        fake.returncode = 0
        fake.stdout = (
            '"rphost.exe","NOT_A_PID","Services","0","123 K"\n'
            '"rphost.exe","42","Services","0","456 K"\n'
        )
        monkeypatch.setattr(mds.subprocess, "run", lambda *a, **kw: fake)
        rphosts = mds.detect_pre_existing_rphosts()
        assert rphosts == [{"pid": 42, "name": "rphost.exe"}]


class TestForceRecycleRphost:
    """Solution A recycle helper (rac graceful → taskkill fallback)."""

    def test_non_windows_no_op(self, monkeypatch):
        monkeypatch.setattr(mds.sys, "platform", "linux")
        result = mds.force_recycle_rphost_processes([1, 2, 3])
        assert result == {"killed": [], "failed": [], "method": "noop"}

    def test_empty_pids_no_op(self, monkeypatch):
        monkeypatch.setattr(mds.sys, "platform", "win32")
        # Should NOT call subprocess at all
        called = []
        monkeypatch.setattr(
            mds.subprocess,
            "run",
            lambda *a, **kw: called.append(a) or MagicMock(returncode=0),
        )
        result = mds.force_recycle_rphost_processes([])
        assert result == {"killed": [], "failed": [], "method": "noop"}
        assert called == []

    def test_taskkill_fallback_when_rac_missing(self, monkeypatch):
        monkeypatch.setattr(mds.sys, "platform", "win32")
        monkeypatch.setattr(mds, "_find_rac_exe", lambda: None)
        fake = MagicMock(returncode=0, stdout="SUCCESS", stderr="")
        monkeypatch.setattr(mds.subprocess, "run", lambda *a, **kw: fake)
        result = mds.force_recycle_rphost_processes([100, 200])
        assert result["killed"] == [100, 200]
        assert result["failed"] == []
        assert result["method"] == "taskkill"

    def test_taskkill_partial_failure(self, monkeypatch):
        monkeypatch.setattr(mds.sys, "platform", "win32")
        monkeypatch.setattr(mds, "_find_rac_exe", lambda: None)
        call_count = {"n": 0}

        def _run(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return MagicMock(returncode=0, stdout="ok", stderr="")
            return MagicMock(returncode=128, stdout="", stderr="ERROR: not found")

        monkeypatch.setattr(mds.subprocess, "run", _run)
        result = mds.force_recycle_rphost_processes([100, 200])
        assert result["killed"] == [100]
        assert result["failed"] == [{"pid": 200, "error": "ERROR: not found"}]
        assert result["method"] == "taskkill"

    def test_taskkill_subprocess_exception(self, monkeypatch):
        monkeypatch.setattr(mds.sys, "platform", "win32")
        monkeypatch.setattr(mds, "_find_rac_exe", lambda: None)

        def _boom(*args, **kwargs):
            raise OSError("permission denied")

        monkeypatch.setattr(mds.subprocess, "run", _boom)
        result = mds.force_recycle_rphost_processes([42])
        assert result["killed"] == []
        assert result["failed"] == [{"pid": 42, "error": "permission denied"}]
        assert result["method"] == "taskkill"

    def test_dry_run_returns_would_kill_without_subprocess(self, monkeypatch):
        # Fix #4 §12.8: dry_run mode для preview без destructive ops
        monkeypatch.setattr(mds.sys, "platform", "win32")
        called = []
        monkeypatch.setattr(
            mds.subprocess, "run", lambda *a, **kw: called.append(a) or MagicMock(returncode=0)
        )
        result = mds.force_recycle_rphost_processes([100, 200], dry_run=True)
        assert result["method"] == "dry_run"
        assert result["would_kill"] == [100, 200]
        assert result["killed"] == []
        assert result["failed"] == []
        assert "dry_run=True" in result["note"]
        # Critical: subprocess MUST NOT have been called
        assert called == []

    def test_dry_run_with_empty_pids_no_op(self, monkeypatch):
        monkeypatch.setattr(mds.sys, "platform", "win32")
        result = mds.force_recycle_rphost_processes([], dry_run=True)
        # Empty pids → noop (early return) даже при dry_run
        assert result["method"] == "noop"


class TestRacRecycle:
    """Solution A — rac process turn-off path (no admin required)."""

    def test_rac_full_chain_success(self, monkeypatch):
        monkeypatch.setattr(mds.sys, "platform", "win32")
        monkeypatch.setattr(mds, "_find_rac_exe", lambda: "C:/fake/rac.exe")

        # Mock cluster list, process list, turn-off in sequence
        call_log = []

        def _run(args, **kwargs):
            call_log.append(args)
            cmd = args[1] if len(args) > 1 else ""
            if cmd == "cluster":
                return MagicMock(
                    returncode=0,
                    stdout=("cluster : 11111111-2222-3333-4444-555555555555\nhost : LAB\n"),
                )
            if cmd == "process" and "list" in args:
                return MagicMock(
                    returncode=0,
                    stdout=(
                        "process : aaaa1111-bbbb-cccc-dddd-eeeeeeeeeeee\n"
                        "pid : 100\n"
                        "process : ffff2222-bbbb-cccc-dddd-eeeeeeeeeeee\n"
                        "pid : 200\n"
                    ),
                )
            # turn-off
            return MagicMock(returncode=0, stdout="", stderr="")

        monkeypatch.setattr(mds.subprocess, "run", _run)
        result = mds.force_recycle_rphost_processes([100, 200])
        assert result["killed"] == [100, 200]
        assert result["failed"] == []
        assert result["method"] == "rac.turn_off"
        # Verify rac was actually invoked for cluster + process list + 2 turn-offs
        assert len(call_log) == 4

    def test_rac_unknown_pid_recorded_as_failed(self, monkeypatch):
        monkeypatch.setattr(mds.sys, "platform", "win32")
        monkeypatch.setattr(mds, "_find_rac_exe", lambda: "C:/fake/rac.exe")
        monkeypatch.setattr(
            mds, "_rac_get_cluster_uuid", lambda *a: "11111111-2222-3333-4444-555555555555"
        )
        monkeypatch.setattr(mds, "_rac_list_processes_by_pid", lambda *a: {})  # no PIDs found
        result = mds.force_recycle_rphost_processes([999])
        assert result["killed"] == []
        assert result["method"] == "rac.turn_off"
        assert len(result["failed"]) == 1
        assert "no cluster process UUID" in result["failed"][0]["error"]

    def test_rac_falls_back_to_taskkill_when_cluster_unknown(self, monkeypatch):
        monkeypatch.setattr(mds.sys, "platform", "win32")
        monkeypatch.setattr(mds, "_find_rac_exe", lambda: "C:/fake/rac.exe")
        monkeypatch.setattr(mds, "_rac_get_cluster_uuid", lambda *a: None)
        # Now should fall through to taskkill
        fake = MagicMock(returncode=0, stdout="ok", stderr="")
        monkeypatch.setattr(mds.subprocess, "run", lambda *a, **kw: fake)
        result = mds.force_recycle_rphost_processes([42])
        assert result["killed"] == [42]
        assert result["method"] == "taskkill"

    def test_find_rac_exe_returns_none_when_no_files_exist(self, monkeypatch):
        monkeypatch.setattr("os.path.isfile", lambda p: False)
        assert mds._find_rac_exe() is None

    def test_rac_get_cluster_uuid_parses_first_uuid(self, monkeypatch):
        fake = MagicMock(
            returncode=0,
            stdout=(
                "cluster                                   : abcd1234-5678-90ab-cdef-1234567890ab\n"
                "host                                      : LAB\n"
                "port                                      : 1541\n"
            ),
        )
        monkeypatch.setattr(mds.subprocess, "run", lambda *a, **kw: fake)
        result = mds._rac_get_cluster_uuid("/fake/rac")
        assert result == "abcd1234-5678-90ab-cdef-1234567890ab"

    def test_rac_get_cluster_uuid_returns_none_on_failure(self, monkeypatch):
        fake = MagicMock(returncode=1, stdout="", stderr="connection refused")
        monkeypatch.setattr(mds.subprocess, "run", lambda *a, **kw: fake)
        assert mds._rac_get_cluster_uuid("/fake/rac") is None

    def test_rac_auth_args_empty_when_no_env(self, monkeypatch):
        monkeypatch.delenv("RAC_CLUSTER_USER", raising=False)
        monkeypatch.delenv("RAC_CLUSTER_PWD", raising=False)
        assert mds._rac_auth_args() == []

    def test_rac_auth_args_full_pair(self, monkeypatch):
        monkeypatch.setenv("RAC_CLUSTER_USER", "Admin")
        monkeypatch.setenv("RAC_CLUSTER_PWD", "secret123")
        assert mds._rac_auth_args() == [
            "--cluster-user=Admin",
            "--cluster-pwd=secret123",
        ]

    def test_rac_auth_args_user_only(self, monkeypatch):
        monkeypatch.setenv("RAC_CLUSTER_USER", "ReadOnly")
        monkeypatch.delenv("RAC_CLUSTER_PWD", raising=False)
        assert mds._rac_auth_args() == ["--cluster-user=ReadOnly"]

    def test_service_restart_success(self, monkeypatch):
        # Path 2: BSL_DEBUG_ALLOW_SERVICE_RESTART=true + no rac → service.restart
        monkeypatch.setattr(mds.sys, "platform", "win32")
        monkeypatch.setattr(mds, "_find_rac_exe", lambda: None)
        monkeypatch.setenv("BSL_DEBUG_ALLOW_SERVICE_RESTART", "true")
        captured = []

        def _run(args, **kwargs):
            captured.append(list(args))
            return MagicMock(returncode=0, stdout="OK\n", stderr="")

        monkeypatch.setattr(mds.subprocess, "run", _run)
        result = mds.force_recycle_rphost_processes([100, 200])
        assert result["killed"] == [100, 200]
        assert result["failed"] == []
        assert result["method"] == "service.restart"
        assert any("Restart-Service" in " ".join(c) for c in captured)

    def test_service_restart_failure_records_per_pid_error(self, monkeypatch):
        monkeypatch.setattr(mds.sys, "platform", "win32")
        monkeypatch.setenv("BSL_DEBUG_ALLOW_SERVICE_RESTART", "true")
        fake = MagicMock(returncode=1, stdout="", stderr="Cannot open service. Access denied.")
        monkeypatch.setattr(mds.subprocess, "run", lambda *a, **kw: fake)
        result = mds._recycle_via_service([42, 99])
        assert result["killed"] == []
        assert result["method"] == "service.restart"
        assert len(result["failed"]) == 2
        assert all("Access denied" in f["error"] for f in result["failed"])

    def test_service_restart_skipped_when_env_unset(self, monkeypatch):
        # env unset → wrapper falls through to taskkill, NOT service.restart
        monkeypatch.setattr(mds.sys, "platform", "win32")
        monkeypatch.setattr(mds, "_find_rac_exe", lambda: None)
        monkeypatch.delenv("BSL_DEBUG_ALLOW_SERVICE_RESTART", raising=False)
        fake = MagicMock(returncode=0, stdout="ok", stderr="")
        monkeypatch.setattr(mds.subprocess, "run", lambda *a, **kw: fake)
        result = mds.force_recycle_rphost_processes([42])
        assert result["method"] == "taskkill"  # NOT service.restart

    def test_rac_auth_args_injected_into_turn_off(self, monkeypatch):
        # Verify _rac_auth_args output присутствует в subprocess call args
        monkeypatch.setenv("RAC_CLUSTER_USER", "Admin")
        monkeypatch.setenv("RAC_CLUSTER_PWD", "pwd")
        captured: list = []

        def _run(args, **kwargs):
            captured.append(list(args))
            return MagicMock(returncode=0, stdout="", stderr="")

        monkeypatch.setattr(mds.subprocess, "run", _run)
        mds._recycle_via_rac("/fake/rac", "C-UUID", [42], {42: "P-UUID"})
        assert captured, "subprocess.run was not called"
        cmd = captured[0]
        assert "--cluster-user=Admin" in cmd
        assert "--cluster-pwd=pwd" in cmd
        assert "turn-off" in cmd

    def test_rac_list_processes_by_pid_parses_blocks(self, monkeypatch):
        fake = MagicMock(
            returncode=0,
            stdout=(
                "process              : aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n"
                "host                 : LAB\n"
                "pid                  : 12345\n"
                "use                  : used\n"
                "process              : ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee\n"
                "pid                  : 67890\n"
            ),
        )
        monkeypatch.setattr(mds.subprocess, "run", lambda *a, **kw: fake)
        result = mds._rac_list_processes_by_pid("/fake/rac", "cluster-uuid")
        assert result == {
            12345: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            67890: "ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee",
        }


@pytest.mark.asyncio
class TestDebugConnectPreflight:
    """Integration: debug_connect surfaces preflight + drives force-recycle."""

    async def _setup_client_mocks(self, monkeypatch, registered=True):
        """Wire RDBGClient methods to in-memory fakes; return captured kills."""
        from mcp_debug_server import RDBGClient

        async def _api_version(self):
            return "8.3.27"

        async def _debug_id(self):
            return mds.ZERO_UUID

        async def _attach(self, cleanup_stale=True):
            self._attached = True
            self._registered = registered
            return {
                "result": "registered" if registered else "ibInDebug",
                "session_id": self.session_id,
                "fully_registered": registered,
            }

        async def _init_settings(self):
            return None

        async def _clear_bons(self):
            return None

        async def _set_aas(self, **kw):
            return None

        async def _targets(self):
            return []

        async def _attach_targets(self, ids, attach=True):
            return True

        async def _close(self):
            pass

        monkeypatch.setattr(RDBGClient, "get_api_version", _api_version)
        monkeypatch.setattr(RDBGClient, "get_debug_id", _debug_id)
        monkeypatch.setattr(RDBGClient, "attach", _attach)
        monkeypatch.setattr(RDBGClient, "init_settings", _init_settings)
        monkeypatch.setattr(RDBGClient, "clear_break_on_next_statement", _clear_bons)
        monkeypatch.setattr(RDBGClient, "set_auto_attach_settings", _set_aas)
        monkeypatch.setattr(RDBGClient, "get_targets", _targets)
        monkeypatch.setattr(RDBGClient, "attach_debug_targets", _attach_targets)
        monkeypatch.setattr(RDBGClient, "close", _close)

        # Roadmap 260511 §3.1: mock alias validation → skipped (rac unreachable
        # in unit-test env) so tests using arbitrary aliases like "X" proceed.
        monkeypatch.setattr(
            mds,
            "_validate_infobase_alias",
            lambda alias: {"status": "skipped", "reason": "rac_exe_not_found"},
        )

        # Reset the module-level singleton so every test starts cold
        mds._client = None

    async def test_no_rphost_no_warning_no_recycle(self, monkeypatch):
        await self._setup_client_mocks(monkeypatch)
        monkeypatch.setattr(mds, "detect_pre_existing_rphosts", lambda: [])
        kill_calls = []
        monkeypatch.setattr(
            mds,
            "force_recycle_rphost_processes",
            lambda pids: kill_calls.append(pids) or {"killed": [], "failed": []},
        )

        # Skip the 3-second sleep
        async def _no_sleep(_):
            return None

        monkeypatch.setattr(mds.asyncio, "sleep", _no_sleep)

        raw = await mds.debug_connect(infobase_alias="X")
        result = json.loads(raw)
        assert result["status"] == "connected"
        assert "pre_existing_rphost_warning" not in result
        assert "force_recycle" not in result
        assert kill_calls == []

    async def test_pre_existing_no_force_emits_warning(self, monkeypatch):
        await self._setup_client_mocks(monkeypatch)
        monkeypatch.setattr(
            mds, "detect_pre_existing_rphosts", lambda: [{"pid": 999, "name": "rphost.exe"}]
        )
        kill_calls = []
        monkeypatch.setattr(
            mds,
            "force_recycle_rphost_processes",
            lambda pids: kill_calls.append(pids) or {"killed": [], "failed": []},
        )

        async def _no_sleep(_):
            return None

        monkeypatch.setattr(mds.asyncio, "sleep", _no_sleep)

        raw = await mds.debug_connect(infobase_alias="X")
        result = json.loads(raw)
        assert "pre_existing_rphost_warning" in result
        warning = result["pre_existing_rphost_warning"]
        assert warning["pre_existing_pids"] == [999]
        assert "next_steps" in warning and len(warning["next_steps"]) >= 3
        assert "roadmap_ref" in warning
        # Crucially: NO recycle attempted
        assert kill_calls == []
        assert "force_recycle" not in result

    async def test_force_recycle_invokes_kill(self, monkeypatch):
        await self._setup_client_mocks(monkeypatch)
        monkeypatch.setattr(
            mds,
            "detect_pre_existing_rphosts",
            lambda: [{"pid": 111, "name": "rphost.exe"}, {"pid": 222, "name": "rphost.exe"}],
        )
        kill_calls = []

        def _kill(pids, **kw):
            kill_calls.append(list(pids))
            return {"killed": list(pids), "failed": []}

        monkeypatch.setattr(mds, "force_recycle_rphost_processes", _kill)
        slept = []

        async def _record_sleep(secs):
            slept.append(secs)

        monkeypatch.setattr(mds.asyncio, "sleep", _record_sleep)

        raw = await mds.debug_connect(infobase_alias="X", force_recycle_rphost=True)
        result = json.loads(raw)
        assert kill_calls == [[111, 222]]
        # Wait happened (should be ~3s for ragent to spawn fresh worker)
        assert slept and slept[0] >= 1.0
        assert "force_recycle" in result
        rec = result["force_recycle"]
        assert rec["requested_pids"] == [111, 222]
        assert rec["killed"] == [111, 222]
        assert rec["failed"] == []
        # When force-recycle ran, preflight warning is suppressed
        assert "pre_existing_rphost_warning" not in result

    async def test_force_recycle_skipped_when_not_registered(self, monkeypatch):
        # ibInDebug → _registered=False → recycle MUST NOT happen (filter not pushed)
        await self._setup_client_mocks(monkeypatch, registered=False)
        monkeypatch.setattr(
            mds, "detect_pre_existing_rphosts", lambda: [{"pid": 333, "name": "rphost.exe"}]
        )
        kill_calls = []
        monkeypatch.setattr(
            mds,
            "force_recycle_rphost_processes",
            lambda pids: kill_calls.append(pids) or {"killed": [], "failed": []},
        )

        async def _no_sleep(_):
            return None

        monkeypatch.setattr(mds.asyncio, "sleep", _no_sleep)

        raw = await mds.debug_connect(infobase_alias="X", force_recycle_rphost=True)
        result = json.loads(raw)
        assert kill_calls == []  # registered=False guard works
        assert "force_recycle" not in result


# ---------------------------------------------------------------------------
# Roadmap 260511 §3.1 + §3.2: infobase alias validation + recycle_strategy
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestInfobaseAliasValidation:
    """§3.1 — debug_connect validates alias against rac infobase list."""

    async def _setup(self, monkeypatch, registered=True):
        """Same as TestDebugConnectPreflight._setup_client_mocks but без
        дефолтного alias-validation mock — каждый тест ставит свой."""
        from mcp_debug_server import RDBGClient

        async def _api_version(self):
            return "8.3.27"

        async def _debug_id(self):
            return mds.ZERO_UUID

        async def _attach(self, cleanup_stale=True):
            self._attached = True
            self._registered = registered
            return {
                "result": "registered" if registered else "ibInDebug",
                "session_id": self.session_id,
                "fully_registered": registered,
            }

        async def _init_settings(self):
            return None

        async def _clear_bons(self):
            return None

        async def _set_aas(self, **kw):
            return None

        async def _targets(self):
            return []

        async def _attach_targets(self, ids, attach=True):
            return True

        async def _close(self):
            pass

        monkeypatch.setattr(RDBGClient, "get_api_version", _api_version)
        monkeypatch.setattr(RDBGClient, "get_debug_id", _debug_id)
        monkeypatch.setattr(RDBGClient, "attach", _attach)
        monkeypatch.setattr(RDBGClient, "init_settings", _init_settings)
        monkeypatch.setattr(RDBGClient, "clear_break_on_next_statement", _clear_bons)
        monkeypatch.setattr(RDBGClient, "set_auto_attach_settings", _set_aas)
        monkeypatch.setattr(RDBGClient, "get_targets", _targets)
        monkeypatch.setattr(RDBGClient, "attach_debug_targets", _attach_targets)
        monkeypatch.setattr(RDBGClient, "close", _close)
        monkeypatch.setattr(mds, "detect_pre_existing_rphosts", lambda: [])

        async def _no_sleep(_):
            return None

        monkeypatch.setattr(mds.asyncio, "sleep", _no_sleep)
        mds._client = None

    async def test_alias_valid_proceeds_to_connect(self, monkeypatch):
        await self._setup(monkeypatch)
        monkeypatch.setattr(
            mds,
            "_validate_infobase_alias",
            lambda a: {"status": "valid", "uuid": "uuid-1", "name": a},
        )
        raw = await mds.debug_connect(infobase_alias="ИБTransport")
        result = json.loads(raw)
        assert result["status"] == "connected"
        assert result["alias_validation"]["status"] == "valid"

    async def test_alias_invalid_blocks_with_available_list(self, monkeypatch):
        await self._setup(monkeypatch)
        monkeypatch.setattr(
            mds,
            "_validate_infobase_alias",
            lambda a: {"status": "invalid", "available": ["ИБReal", "DevBase"]},
        )
        raw = await mds.debug_connect(infobase_alias="WrongAlias")
        result = json.loads(raw)
        assert result["status"] == "error"
        assert result["reason"] == "infobase_alias_not_found"
        assert result["provided"] == "WrongAlias"
        assert result["available"] == ["ИБReal", "DevBase"]
        assert "hint" in result

    async def test_alias_skipped_proceeds_to_connect(self, monkeypatch):
        # rac.exe not found / cluster unreachable → skipped, не блокирует
        await self._setup(monkeypatch)
        monkeypatch.setattr(
            mds,
            "_validate_infobase_alias",
            lambda a: {"status": "skipped", "reason": "rac_exe_not_found"},
        )
        raw = await mds.debug_connect(infobase_alias="X")
        result = json.loads(raw)
        assert result["status"] == "connected"
        assert result["alias_validation"]["status"] == "skipped"


@pytest.mark.asyncio
class TestRecycleStrategy:
    """§3.2 — recycle_strategy extends force_recycle_rphost coverage."""

    async def _setup(self, monkeypatch, alias_validation=None, registered=True):
        from mcp_debug_server import RDBGClient

        async def _api_version(self):
            return "8.3.27"

        async def _debug_id(self):
            return mds.ZERO_UUID

        async def _attach(self, cleanup_stale=True):
            self._attached = True
            self._registered = registered
            return {
                "result": "registered" if registered else "ibInDebug",
                "session_id": self.session_id,
                "fully_registered": registered,
            }

        async def _init_settings(self):
            return None

        async def _clear_bons(self):
            return None

        async def _set_aas(self, **kw):
            return None

        async def _targets(self):
            return []

        async def _attach_targets(self, ids, attach=True):
            return True

        async def _close(self):
            pass

        for name, fn in (
            ("get_api_version", _api_version),
            ("get_debug_id", _debug_id),
            ("attach", _attach),
            ("init_settings", _init_settings),
            ("clear_break_on_next_statement", _clear_bons),
            ("set_auto_attach_settings", _set_aas),
            ("get_targets", _targets),
            ("attach_debug_targets", _attach_targets),
            ("close", _close),
        ):
            monkeypatch.setattr(RDBGClient, name, fn)

        async def _no_sleep(_):
            return None

        monkeypatch.setattr(mds.asyncio, "sleep", _no_sleep)
        validation = alias_validation or {"status": "skipped", "reason": "rac_exe_not_found"}
        monkeypatch.setattr(mds, "_validate_infobase_alias", lambda a: validation)
        mds._client = None

    async def test_default_auto_no_force_means_none(self, monkeypatch):
        # auto + force_recycle_rphost=False → recycle_strategy resolved to "none"
        await self._setup(monkeypatch)
        monkeypatch.setattr(
            mds, "detect_pre_existing_rphosts", lambda: [{"pid": 100, "name": "rphost.exe"}]
        )
        kill_calls = []
        monkeypatch.setattr(
            mds,
            "force_recycle_rphost_processes",
            lambda pids, dry_run=False: kill_calls.append(pids) or {"killed": [], "failed": []},
        )
        raw = await mds.debug_connect(infobase_alias="X")
        result = json.loads(raw)
        assert kill_calls == []  # "none" → no kill
        # Warning emitted because pre_existing but strategy=none
        assert "pre_existing_rphost_warning" in result

    async def test_backward_compat_force_recycle_true(self, monkeypatch):
        # auto + force_recycle_rphost=True → resolves to "pre_existing"
        await self._setup(monkeypatch)
        monkeypatch.setattr(
            mds,
            "detect_pre_existing_rphosts",
            lambda: [{"pid": 100, "name": "rphost.exe"}, {"pid": 200, "name": "rphost.exe"}],
        )
        kill_calls = []
        monkeypatch.setattr(
            mds,
            "force_recycle_rphost_processes",
            lambda pids, dry_run=False: (
                kill_calls.append(pids) or {"killed": list(pids), "failed": []}
            ),
        )
        raw = await mds.debug_connect(infobase_alias="X", force_recycle_rphost=True)
        result = json.loads(raw)
        assert kill_calls == [[100, 200]]
        assert result["force_recycle"]["strategy"] == "pre_existing"

    async def test_all_rphosts_of_ib_requires_valid_alias(self, monkeypatch):
        # strategy=all_rphosts_of_ib + alias=skipped → returns error
        await self._setup(
            monkeypatch, alias_validation={"status": "skipped", "reason": "rac_exe_not_found"}
        )
        raw = await mds.debug_connect(infobase_alias="X", recycle_strategy="all_rphosts_of_ib")
        result = json.loads(raw)
        assert result["status"] == "error"
        assert result["reason"] == "recycle_strategy_requires_valid_alias"

    async def test_all_rphosts_of_ib_resolves_via_rac(self, monkeypatch):
        # strategy=all_rphosts_of_ib + valid alias → kills via _rac_list_rphosts_of_infobase
        await self._setup(
            monkeypatch, alias_validation={"status": "valid", "uuid": "ib-uuid-1", "name": "ИБReal"}
        )
        monkeypatch.setattr(mds, "detect_pre_existing_rphosts", lambda: [])
        monkeypatch.setattr(mds, "_find_rac_exe", lambda: "/fake/rac.exe")
        monkeypatch.setattr(mds, "_rac_get_cluster_uuid", lambda exe: "cluster-uuid")
        monkeypatch.setattr(
            mds, "_rac_list_rphosts_of_infobase", lambda exe, cluster, ib_uuid: [555, 666]
        )
        kill_calls = []
        monkeypatch.setattr(
            mds,
            "force_recycle_rphost_processes",
            lambda pids, dry_run=False: (
                kill_calls.append(list(pids)) or {"killed": list(pids), "failed": []}
            ),
        )
        raw = await mds.debug_connect(infobase_alias="ИБReal", recycle_strategy="all_rphosts_of_ib")
        result = json.loads(raw)
        assert result["status"] == "connected"
        assert kill_calls == [[555, 666]]
        assert result["force_recycle"]["strategy"] == "all_rphosts_of_ib"
        assert result["force_recycle"]["requested_pids"] == [555, 666]

    async def test_invalid_strategy_value_blocks(self, monkeypatch):
        await self._setup(monkeypatch)
        raw = await mds.debug_connect(infobase_alias="X", recycle_strategy="bogus")
        result = json.loads(raw)
        assert result["status"] == "error"
        assert result["reason"] == "invalid_recycle_strategy"
        assert "all_rphosts_of_ib" in result["allowed"]

    async def test_all_rphosts_of_cluster_combines_snapshot_and_rac(self, monkeypatch):
        """HIGH RISK strategy — kills snapshot + cluster-wide rac process list,
        dedup'ит pids между источниками. Smoke coverage для критичной ветки
        (review feedback от code-verify quality-review)."""
        await self._setup(monkeypatch)
        # Snapshot returns pids [100, 200]
        monkeypatch.setattr(
            mds,
            "detect_pre_existing_rphosts",
            lambda: [{"pid": 100, "name": "rphost.exe"}, {"pid": 200, "name": "rphost.exe"}],
        )
        monkeypatch.setattr(mds, "_find_rac_exe", lambda: "/fake/rac.exe")
        monkeypatch.setattr(mds, "_rac_get_cluster_uuid", lambda exe: "c-uuid")
        # rac returns pids [200 (dup), 300, 400] — 200 уже в snapshot
        monkeypatch.setattr(
            mds,
            "_rac_list_processes_by_pid",
            lambda exe, cl: {200: "p2-uuid", 300: "p3-uuid", 400: "p4-uuid"},
        )
        kill_calls = []
        monkeypatch.setattr(
            mds,
            "force_recycle_rphost_processes",
            lambda pids, dry_run=False: (
                kill_calls.append(list(pids)) or {"killed": list(pids), "failed": []}
            ),
        )
        raw = await mds.debug_connect(infobase_alias="X", recycle_strategy="all_rphosts_of_cluster")
        result = json.loads(raw)
        assert result["status"] == "connected"
        # 100, 200 from snapshot + 300, 400 from rac (200 dedup'ed)
        assert kill_calls == [[100, 200, 300, 400]]
        assert result["force_recycle"]["strategy"] == "all_rphosts_of_cluster"


# ---------------------------------------------------------------------------
# Roadmap 260511 §3.1: _validate_infobase_alias helper unit tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestPostSpawnAutoAttach:
    """Roadmap 260511 §P0.4 — periodic auto-attach polling в _ping_loop.

    Closes residual RC2: HTTP-service spawned rphost виден в get_targets,
    но НЕ emit'ил targetStarted к нашей session → без polling никогда
    не attach'ится → BPs не fire.
    """

    def _make_client(self):
        c = RDBGClient(infobase_alias="ИБTest")
        c._attached = True
        c._registered = True
        return c

    async def test_post_spawn_attaches_new_targets(self, monkeypatch):
        c = self._make_client()
        c._known_attached_targets.add("already-attached-id")

        # get_targets returns 2: один уже attached, один новый
        async def _get_targets(self):
            return [{"id": "already-attached-id"}, {"id": "new-spawn-id"}]

        # attach_debug_targets captures call
        attach_calls = []

        async def _attach(self, uuids, attach=True):
            attach_calls.append((list(uuids), attach))
            return True

        monkeypatch.setattr(RDBGClient, "get_targets", _get_targets)
        monkeypatch.setattr(RDBGClient, "attach_debug_targets", _attach)

        attached_count = await c._post_spawn_auto_attach()
        assert attached_count == 1
        assert attach_calls == [(["new-spawn-id"], True)]
        assert "new-spawn-id" in c._known_attached_targets

    async def test_post_spawn_noop_when_all_attached(self, monkeypatch):
        c = self._make_client()
        c._known_attached_targets.update({"t1", "t2"})

        async def _get_targets(self):
            return [{"id": "t1"}, {"id": "t2"}]

        attach_calls = []

        async def _attach(self, uuids, attach=True):
            attach_calls.append(uuids)
            return True

        monkeypatch.setattr(RDBGClient, "get_targets", _get_targets)
        monkeypatch.setattr(RDBGClient, "attach_debug_targets", _attach)

        attached_count = await c._post_spawn_auto_attach()
        assert attached_count == 0
        assert attach_calls == []

    async def test_post_spawn_handles_get_targets_failure(self, monkeypatch):
        c = self._make_client()

        async def _get_targets(self):
            raise RuntimeError("connection refused")

        monkeypatch.setattr(RDBGClient, "get_targets", _get_targets)

        attached_count = await c._post_spawn_auto_attach()
        assert attached_count == 0  # graceful — return 0, не raise

    async def test_post_spawn_handles_attach_failure(self, monkeypatch):
        c = self._make_client()

        async def _get_targets(self):
            return [{"id": "new-id"}]

        async def _attach(self, uuids, attach=True):
            raise RuntimeError("RDBG 500")

        monkeypatch.setattr(RDBGClient, "get_targets", _get_targets)
        monkeypatch.setattr(RDBGClient, "attach_debug_targets", _attach)

        attached_count = await c._post_spawn_auto_attach()
        assert attached_count == 0
        # known_attached_targets НЕ обновлён (attach failed)
        assert "new-id" not in c._known_attached_targets

    async def test_post_spawn_skips_targets_without_id(self, monkeypatch):
        c = self._make_client()

        async def _get_targets(self):
            return [{"id": ""}, {"name": "no-id-field"}, {"id": "real-id"}]

        attach_calls = []

        async def _attach(self, uuids, attach=True):
            attach_calls.append(list(uuids))
            return True

        monkeypatch.setattr(RDBGClient, "get_targets", _get_targets)
        monkeypatch.setattr(RDBGClient, "attach_debug_targets", _attach)

        attached_count = await c._post_spawn_auto_attach()
        assert attached_count == 1
        assert attach_calls == [["real-id"]]


class TestValidateInfobaseAlias:
    def test_skipped_when_rac_not_found(self, monkeypatch):
        monkeypatch.setattr(mds, "_find_rac_exe", lambda: None)
        monkeypatch.delenv("DEBUG_INFOBASE_ALIASES", raising=False)
        result = mds._validate_infobase_alias("anything")
        assert result["status"] == "skipped"
        assert result["reason"] == "rac_exe_not_found"

    def test_skipped_when_cluster_unreachable(self, monkeypatch):
        monkeypatch.setattr(mds, "_find_rac_exe", lambda: "/fake/rac.exe")
        monkeypatch.setattr(mds, "_rac_get_cluster_uuid", lambda exe: None)
        monkeypatch.delenv("DEBUG_INFOBASE_ALIASES", raising=False)
        result = mds._validate_infobase_alias("X")
        assert result["status"] == "skipped"
        assert result["reason"] == "cluster_unreachable"

    def test_skipped_when_empty_infobase_list(self, monkeypatch):
        monkeypatch.setattr(mds, "_find_rac_exe", lambda: "/fake/rac.exe")
        monkeypatch.setattr(mds, "_rac_get_cluster_uuid", lambda exe: "c1")
        monkeypatch.setattr(mds, "_rac_list_infobases", lambda exe, cl: [])
        monkeypatch.delenv("DEBUG_INFOBASE_ALIASES", raising=False)
        result = mds._validate_infobase_alias("X")
        assert result["status"] == "skipped"
        assert result["reason"] == "empty_infobase_list"

    def test_valid_when_alias_matches(self, monkeypatch):
        monkeypatch.setattr(mds, "_find_rac_exe", lambda: "/fake/rac.exe")
        monkeypatch.setattr(mds, "_rac_get_cluster_uuid", lambda exe: "c1")
        monkeypatch.setattr(
            mds,
            "_rac_list_infobases",
            lambda exe, cl: [{"uuid": "u1", "name": "ИБOne"}, {"uuid": "u2", "name": "Other"}],
        )
        monkeypatch.delenv("DEBUG_INFOBASE_ALIASES", raising=False)
        result = mds._validate_infobase_alias("ИБOne")
        assert result["status"] == "valid"
        assert result["uuid"] == "u1"
        assert result["name"] == "ИБOne"

    def test_invalid_when_alias_not_in_list(self, monkeypatch):
        monkeypatch.setattr(mds, "_find_rac_exe", lambda: "/fake/rac.exe")
        monkeypatch.setattr(mds, "_rac_get_cluster_uuid", lambda exe: "c1")
        monkeypatch.setattr(
            mds,
            "_rac_list_infobases",
            lambda exe, cl: [{"uuid": "u1", "name": "ИБOne"}, {"uuid": "u2", "name": "Other"}],
        )
        monkeypatch.delenv("DEBUG_INFOBASE_ALIASES", raising=False)
        result = mds._validate_infobase_alias("Wrong")
        assert result["status"] == "invalid"
        assert result["available"] == ["ИБOne", "Other"]

    def test_env_alias_mapping_resolves(self, monkeypatch):
        """§3.7 P2: DEBUG_INFOBASE_ALIASES env translates short → long."""
        monkeypatch.setattr(mds, "_find_rac_exe", lambda: "/fake/rac.exe")
        monkeypatch.setattr(mds, "_rac_get_cluster_uuid", lambda exe: "c1")
        monkeypatch.setattr(
            mds,
            "_rac_list_infobases",
            lambda exe, cl: [{"uuid": "u1", "name": "ИБLongCyrillicName"}],
        )
        monkeypatch.setenv("DEBUG_INFOBASE_ALIASES", "Short:ИБLongCyrillicName;Other:OtherLong")
        result = mds._validate_infobase_alias("Short")
        assert result["status"] == "valid"
        assert result["name"] == "ИБLongCyrillicName"
        assert result["alias_resolved_from_env"] is True

    def test_env_alias_mapping_no_match_passes_through(self, monkeypatch):
        """Если alias не в env mapping — используется как есть."""
        monkeypatch.setattr(mds, "_find_rac_exe", lambda: "/fake/rac.exe")
        monkeypatch.setattr(mds, "_rac_get_cluster_uuid", lambda exe: "c1")
        monkeypatch.setattr(
            mds, "_rac_list_infobases", lambda exe, cl: [{"uuid": "u1", "name": "ИБDirect"}]
        )
        monkeypatch.setenv("DEBUG_INFOBASE_ALIASES", "Other:OtherLong")
        result = mds._validate_infobase_alias("ИБDirect")
        assert result["status"] == "valid"
        assert result.get("alias_resolved_from_env") is False


# ---------------------------------------------------------------------------
# §13.x HMR-restart recovery: active session persistence
# ---------------------------------------------------------------------------


@pytest.fixture
def isolated_active_path(tmp_path, monkeypatch):
    """Redirect _ACTIVE_SESSION_PATH to a tmp file + reset _client singleton."""
    target = tmp_path / "active.json"
    monkeypatch.setattr(mds, "_ACTIVE_SESSION_PATH", str(target))
    monkeypatch.setattr(mds, "_client", None)
    return target


class TestActiveSessionPersistence:
    def test_persist_writes_state_for_registered_client(self, isolated_active_path):
        c = RDBGClient(debug_url="http://h:1550", infobase_alias="ALIAS")
        c.session_id = "fixed-uuid-for-test"
        c._attached = True
        c._registered = True
        mds._persist_active_session(c)
        assert isolated_active_path.is_file()
        state = json.loads(isolated_active_path.read_text(encoding="utf-8"))
        assert state["session_id"] == "fixed-uuid-for-test"
        assert state["debug_url"] == "http://h:1550"
        assert state["infobase_alias"] == "ALIAS"
        assert isinstance(state["persisted_at"], (int, float))

    def test_persist_noop_when_not_registered(self, isolated_active_path):
        c = RDBGClient()
        c._attached = True
        c._registered = False  # ibInDebug case
        mds._persist_active_session(c)
        assert not isolated_active_path.exists()

    def test_persist_noop_when_not_attached(self, isolated_active_path):
        c = RDBGClient()
        c._attached = False
        c._registered = False
        mds._persist_active_session(c)
        assert not isolated_active_path.exists()

    def test_persist_atomic_via_replace(self, isolated_active_path):
        # Pre-existing file must be overwritten atomically (no tmp leftover)
        isolated_active_path.write_text('{"session_id": "old"}', encoding="utf-8")
        c = RDBGClient(infobase_alias="NEW")
        c.session_id = "new-id"
        c._attached = True
        c._registered = True
        mds._persist_active_session(c)
        state = json.loads(isolated_active_path.read_text(encoding="utf-8"))
        assert state["session_id"] == "new-id"
        # No leftover .tmp
        assert not (isolated_active_path.parent / "active.json.tmp").exists()

    def test_load_returns_none_when_missing(self, isolated_active_path):
        assert mds._load_active_session() is None

    def test_load_returns_none_on_corrupt_json(self, isolated_active_path):
        isolated_active_path.write_text("{not valid json", encoding="utf-8")
        assert mds._load_active_session() is None

    def test_load_returns_none_on_non_dict_root(self, isolated_active_path):
        isolated_active_path.write_text("[1, 2, 3]", encoding="utf-8")
        assert mds._load_active_session() is None

    def test_load_roundtrip(self, isolated_active_path):
        c = RDBGClient(debug_url="http://x:1551", infobase_alias="RT")
        c.session_id = "roundtrip-id"
        c._attached = True
        c._registered = True
        mds._persist_active_session(c)
        loaded = mds._load_active_session()
        assert loaded is not None
        assert loaded["session_id"] == "roundtrip-id"
        assert loaded["debug_url"] == "http://x:1551"
        assert loaded["infobase_alias"] == "RT"

    def test_clear_removes_file(self, isolated_active_path):
        isolated_active_path.write_text('{"session_id": "x"}', encoding="utf-8")
        mds._clear_active_session()
        assert not isolated_active_path.exists()

    def test_clear_noop_when_missing(self, isolated_active_path):
        # Must not raise even if file already absent
        mds._clear_active_session()  # no exception
        assert not isolated_active_path.exists()


@pytest.mark.asyncio
class TestAttachDetachLifecyclePersistence:
    """attach() persists on success, detach() clears."""

    async def _client_with_attach_xml(self, result_text: str = "registered"):
        """Build client with _post returning attach result XML."""
        c = RDBGClient(debug_url="http://h:1550", infobase_alias="X")
        attach_xml = ET.fromstring(
            f'<root xmlns:r="http://v8.1c.ru/8.3/debugger/debugRDBGRequestResponse">'
            f"<r:result>{result_text}</r:result>"
            f"</root>"
        )
        c._post = AsyncMock(return_value=attach_xml)
        c._cleanup_stale_session = AsyncMock()
        # Prevent ping_loop spawn (real loop would touch network)
        c._ping_loop = AsyncMock()
        return c

    async def test_attach_persists_on_registered(self, isolated_active_path):
        c = await self._client_with_attach_xml("registered")
        await c.attach(cleanup_stale=False)
        assert isolated_active_path.is_file()
        state = json.loads(isolated_active_path.read_text(encoding="utf-8"))
        assert state["session_id"] == c.session_id
        assert state["infobase_alias"] == "X"

    async def test_attach_no_persist_on_ibindebug(self, isolated_active_path):
        c = await self._client_with_attach_xml("ibInDebug")
        await c.attach(cleanup_stale=False)
        assert c._attached is True
        assert c._registered is False
        # Not registered → no persistence
        assert not isolated_active_path.exists()

    async def test_detach_clears_state(self, isolated_active_path):
        c = await self._client_with_attach_xml("registered")
        await c.attach(cleanup_stale=False)
        assert isolated_active_path.is_file()
        # detach() reuses _post; just need a graceful response
        c._post = AsyncMock(return_value=ET.Element("ok"))
        ok = await c.detach()
        assert ok is True
        assert not isolated_active_path.exists()

    async def test_detach_failure_keeps_state(self, isolated_active_path):
        c = await self._client_with_attach_xml("registered")
        await c.attach(cleanup_stale=False)
        assert isolated_active_path.is_file()
        # detach() failing → state file should still be there for next restart
        c._post = AsyncMock(side_effect=RuntimeError("network down"))
        ok = await c.detach()
        assert ok is False
        assert isolated_active_path.is_file()


class TestGetClientHmrRestore:
    def test_cold_start_no_state_creates_default_client(self, isolated_active_path):
        c = mds._get_client()
        assert c is not None
        assert c._attached is False
        assert c._registered is False

    def test_cold_start_with_state_restores_session(self, isolated_active_path):
        isolated_active_path.write_text(
            json.dumps(
                {
                    "session_id": "restored-uuid",
                    "debug_url": "http://restored:1550",
                    "infobase_alias": "RESTORED",
                    "persisted_at": 0,
                }
            ),
            encoding="utf-8",
        )
        c = mds._get_client()
        assert c.session_id == "restored-uuid"
        assert c.debug_url == "http://restored:1550"
        assert c.infobase_alias == "RESTORED"
        assert c._attached is True
        assert c._registered is True

    def test_cold_start_with_partial_state_falls_back(self, isolated_active_path):
        # state file exists но без session_id → treated as no state
        isolated_active_path.write_text(
            json.dumps(
                {
                    "debug_url": "http://x:1550",
                }
            ),
            encoding="utf-8",
        )
        c = mds._get_client()
        assert c._attached is False
        assert c._registered is False

    def test_subsequent_calls_return_same_client(self, isolated_active_path):
        c1 = mds._get_client()
        c2 = mds._get_client()
        assert c1 is c2


# ---------------------------------------------------------------------------
# §13.x ping() dispatches to _handle_command (root-cause fix 2026-05-10)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestPingDispatch:
    """Manual ping must populate cache, not just drain queue.

    Pre-fix bug: client.ping() returned raw events without dispatch; only
    _ping_loop processed them via a separate handler call. Manual debug_ping
    (MCP tool) drained the RDBG queue and ROBBED _ping_loop of those events,
    leaving _last_stack_by_target / _last_stopped_target_id empty. Subsequent
    debug_stack_trace took the HTTP-fallback path (cache miss), which could
    raise httpx errors with empty body and surface as opaque MCP failure.

    Post-fix: ping() dispatches events inline. Both background loop and
    manual ping populate cache identically.
    """

    async def test_populates_last_stopped_via_handle_command(
        self,
        client,
        monkeypatch,
    ):
        client._post = AsyncMock(return_value=ET.Element("root"))
        stack_dict = {"_tag": "frame", "lineNo": "10"}
        events = [
            {
                "cmdId": "callStackFormed",
                "targetID": GOOD_UUID,
                "callStack": stack_dict,
                "stopByBP": "true",
            }
        ]
        monkeypatch.setattr(mds, "_parse_response", lambda root: events)
        result = await client.ping()
        # Cache populated via dispatched _handle_command
        assert client._last_stopped_target_id == GOOD_UUID
        assert client._last_stack_by_target[GOOD_UUID] == [stack_dict]
        assert GOOD_UUID in client._stopped_targets
        # Original events still returned (no behaviour change for callers)
        assert result == events

    async def test_continues_on_handler_exception(self, client, monkeypatch):
        """Per-event try/except in ping() prevents one bad event from blocking rest."""
        client._post = AsyncMock(return_value=ET.Element("root"))
        events = [
            {"cmdId": "evil1", "targetID": GOOD_UUID},
            {
                "cmdId": "callStackFormed",
                "targetID": ANOTHER_UUID,
                "callStack": [{"_tag": "frame"}],
                "stopByBP": "true",
            },
        ]
        monkeypatch.setattr(mds, "_parse_response", lambda root: events)
        # Make _handle_command raise for the FIRST event only
        real_handle = client._handle_command
        call_count = {"n": 0}

        async def flaky(cmd):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise RuntimeError("simulated handler failure")
            await real_handle(cmd)

        client._handle_command = flaky
        await client.ping()
        # Both events were attempted; second succeeded → cache populated
        assert call_count["n"] == 2
        assert client._last_stopped_target_id == ANOTHER_UUID
        assert ANOTHER_UUID in client._last_stack_by_target

    async def test_empty_events_no_dispatch(self, client, monkeypatch):
        client._post = AsyncMock(return_value=ET.Element("root"))
        monkeypatch.setattr(mds, "_parse_response", lambda root: [])
        result = await client.ping()
        assert result == []
        assert client._last_stopped_target_id is None
        assert client._last_stack_by_target == {}


class TestEvalErrorEnvelope:
    """Graceful error envelope для debug_evaluate / debug_variables (follow-up 2026-06-03).

    RDBG отклоняет eval/variables на НЕ-остановленном таргете (HTTP 400 с XML).
    Раньше это пробрасывалось как opaque MCP-exception; теперь — graceful JSON
    {"error":...} (как у debug_stack_trace). `_rdbg_error_text` извлекает чистый
    <descr> вместо дампа всего XML.
    """

    RDBG_XML = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<exception xmlns="http://v8.1c.ru/8.2/virtual-resource-system" reason="400">'
        '<descr xmlns="http://v8.1c.ru/8.1/data/core">Выполнение вычислений возможно '
        "только в остановленном предмете отладки</descr></exception>"
    )

    def test_rdbg_error_text_extracts_descr(self):
        msg = mds._rdbg_error_text(RuntimeError("RDBG evalExpr 400: " + self.RDBG_XML))
        assert msg == ("Выполнение вычислений возможно только в остановленном предмете отладки")

    def test_rdbg_error_text_collapses_whitespace(self):
        xml = "<descr>line1\n   line2\t  line3</descr>"
        assert mds._rdbg_error_text(RuntimeError(xml)) == "line1 line2 line3"

    def test_rdbg_error_text_truncates_plain(self):
        out = mds._rdbg_error_text(RuntimeError("z" * 1000), limit=50)
        assert out.endswith("…")
        assert len(out) <= 51

    @pytest.mark.asyncio
    async def test_evaluate_graceful_envelope(self, monkeypatch):
        class FakeClient:
            _attached = True
            _registered = True
            last_stopped_target_id = "tgt-1"

            async def eval_expression(self, **kw):
                raise RuntimeError("RDBG evalExpr 400: " + TestEvalErrorEnvelope.RDBG_XML)

        monkeypatch.setattr(mds, "_get_client", lambda: FakeClient())
        data = json.loads(await mds.debug_evaluate("1 + 1"))
        assert "остановленном" in data["error"]
        assert data["error_type"] == "RuntimeError"
        assert data["expression"] == "1 + 1"
        assert data["target_id"] == "tgt-1"

    @pytest.mark.asyncio
    async def test_variables_graceful_envelope(self, monkeypatch):
        class FakeClient:
            _attached = True
            _registered = True
            last_stopped_target_id = "tgt-1"

            async def eval_local_variables(self, **kw):
                raise RuntimeError("RDBG evalLocalVariables 400: " + TestEvalErrorEnvelope.RDBG_XML)

        monkeypatch.setattr(mds, "_get_client", lambda: FakeClient())
        data = json.loads(await mds.debug_variables(expressions=["A"]))
        assert "остановленном" in data["error"]
        assert data["error_type"] == "RuntimeError"
        assert data["target_id"] == "tgt-1"

    @pytest.mark.asyncio
    async def test_evaluate_not_connected_envelope(self, monkeypatch):
        """Рек.#1: не-подключённая сессия → явный not_connected, не маскируется."""

        class FakeClient:
            _attached = False
            _registered = False

        monkeypatch.setattr(mds, "_get_client", lambda: FakeClient())
        data = json.loads(await mds.debug_evaluate("1 + 1"))
        assert data["error_type"] == "not_connected"
        assert "debug_connect" in data["error"]

    @pytest.mark.asyncio
    async def test_no_stopped_target_envelope(self, monkeypatch):
        """Рек.#2: единый envelope для 'No stopped targets' (error_type + target_id)."""

        class FakeClient:
            _attached = True
            _registered = True
            last_stopped_target_id = ""

            async def get_targets(self):
                return []

        monkeypatch.setattr(mds, "_get_client", lambda: FakeClient())
        data = json.loads(await mds.debug_evaluate("1 + 1"))
        assert data["error_type"] == "no_stopped_target"
        assert data["error"] == "No stopped targets"


# ---------------------------------------------------------------------------
# W1.0 refactor helpers (2026-07-08): _resolve_property_id /
# _resolve_stopped_target / _enrich_stack — dedup foundation for A0/A1
# ---------------------------------------------------------------------------


class TestResolvePropertyId:
    def test_empty_resolves_and_switches_to_config_module(self):
        xml_mt, pid = mds._resolve_property_id("ManagerModule", "")
        assert xml_mt == "ConfigModule"
        assert pid == mds.MODULE_PROPERTY_IDS["ManagerModule"]

    def test_zero_uuid_treated_as_unset(self):
        xml_mt, pid = mds._resolve_property_id("CommonModule", mds.ZERO_UUID)
        assert xml_mt == "ConfigModule"
        assert pid == mds.MODULE_PROPERTY_IDS["CommonModule"]

    def test_explicit_property_id_preserved(self):
        xml_mt, pid = mds._resolve_property_id("ManagerModule", GOOD_UUID)
        assert xml_mt == "ManagerModule"
        assert pid == GOOD_UUID

    def test_unknown_module_type_falls_through(self):
        xml_mt, pid = mds._resolve_property_id("NoSuchModule", "")
        assert xml_mt == "NoSuchModule"
        assert pid == ""


class TestResolveStoppedTarget:
    @pytest.mark.asyncio
    async def test_explicit_target_short_circuits(self, client):
        client.get_targets = AsyncMock(return_value=[])
        tid, scanned = await mds._resolve_stopped_target(client, GOOD_UUID)
        assert tid == GOOD_UUID
        assert scanned is None
        client.get_targets.assert_not_called()

    @pytest.mark.asyncio
    async def test_falls_back_to_last_stopped_no_scan(self, client):
        client._last_stopped_target_id = GOOD_UUID
        client.get_targets = AsyncMock(return_value=[])
        tid, scanned = await mds._resolve_stopped_target(client, "")
        assert tid == GOOD_UUID
        assert scanned is None
        client.get_targets.assert_not_called()

    @pytest.mark.asyncio
    async def test_scans_targets_when_nothing_cached(self, client):
        targets = [{"id": ANOTHER_UUID, "state": "StopOnNextLine"}]
        client.get_targets = AsyncMock(return_value=targets)
        tid, scanned = await mds._resolve_stopped_target(client, "")
        assert tid == ANOTHER_UUID
        assert scanned == targets

    @pytest.mark.asyncio
    async def test_returns_empty_and_scanned_when_none_stopped(self, client):
        targets = [{"id": ANOTHER_UUID, "state": "Worked"}]
        client.get_targets = AsyncMock(return_value=targets)
        tid, scanned = await mds._resolve_stopped_target(client, "")
        assert tid == ""
        assert scanned == targets


class TestEnrichStack:
    def test_pass_through_when_no_resolution(self, monkeypatch):
        monkeypatch.setattr(mds.uuid_index, "get_source_info", lambda o, p: None)
        stack = [{"moduleID": {"objectID": "x", "propertyID": "y"}, "lineNo": 5}]
        out = mds._enrich_stack(stack)
        assert "resolved_source" not in out[0]

    def test_enriches_when_resolved(self, monkeypatch):
        info = {"fqn": "Документ.X.МодульМенеджера", "file_path": "X/Mgr.bsl", "exists": True}
        monkeypatch.setattr(mds.uuid_index, "get_source_info", lambda o, p: info)
        stack = [{"moduleID": {"objectID": "x", "propertyID": "y"}, "lineNo": 5}]
        out = mds._enrich_stack(stack)
        assert out[0]["resolved_source"] == info
        assert "resolved_source" not in stack[0]  # original not mutated

    def test_non_dict_frame_passes_through(self, monkeypatch):
        monkeypatch.setattr(mds.uuid_index, "get_source_info", lambda o, p: {"fqn": "z"})
        out = mds._enrich_stack(["not-a-dict"])
        assert out == ["not-a-dict"]


# ---------------------------------------------------------------------------
# B2 (2026-07-08 §7.5): _apply_line_offset + line_offsets persist/restore
# ---------------------------------------------------------------------------


class TestApplyLineOffset:
    def test_no_offsets_attr_returns_unchanged(self, client):
        assert not hasattr(client, "_line_offsets") or not client._line_offsets
        line, off = mds._apply_line_offset(client, "obj", 42)
        assert (line, off) == (42, 0)

    def test_offset_applied(self, client):
        client._line_offsets = {"obj": 3}
        line, off = mds._apply_line_offset(client, "obj", 67)
        assert (line, off) == (70, 3)

    def test_offset_for_other_object_not_applied(self, client):
        client._line_offsets = {"other": 5}
        line, off = mds._apply_line_offset(client, "obj", 42)
        assert (line, off) == (42, 0)

    def test_negative_offset(self, client):
        client._line_offsets = {"obj": -2}
        line, off = mds._apply_line_offset(client, "obj", 10)
        assert (line, off) == (8, -2)


class TestLineOffsetsPersistence:
    def test_persist_includes_offsets_and_load_restores(self, client, tmp_path, monkeypatch):
        path = str(tmp_path / ".active.json")
        monkeypatch.setattr(mds, "_ACTIVE_SESSION_PATH", path)
        client._attached = True
        client._registered = True
        client.session_id = "sess-1"
        client._line_offsets = {"objA": 3, "objB": -1}
        mds._persist_active_session(client)
        loaded = mds._load_active_session()
        assert loaded["line_offsets"] == {"objA": 3, "objB": -1}
        assert loaded["session_id"] == "sess-1"

    def test_persist_empty_offsets_when_absent(self, client, tmp_path, monkeypatch):
        path = str(tmp_path / ".active.json")
        monkeypatch.setattr(mds, "_ACTIVE_SESSION_PATH", path)
        client._attached = True
        client._registered = True
        client.session_id = "sess-2"
        mds._persist_active_session(client)
        loaded = mds._load_active_session()
        assert loaded["line_offsets"] == {}
