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

import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import AsyncMock, patch

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
            expression="ТекущаяДата()", target_uuid=GOOD_UUID,
        )
        client.attach_debug_targets.assert_awaited_once_with([GOOD_UUID])

    async def test_eval_local_variables_uses_last_stopped(self, client):
        client._last_stopped_target_id = GOOD_UUID
        client.attach_debug_targets = AsyncMock(return_value=True)
        await client.eval_local_variables()
        # Re-attach probed for fallback target
        client.attach_debug_targets.assert_awaited_once_with([GOOD_UUID])

    async def test_eval_expression_raises_when_no_target(self, client):
        with pytest.raises(ValueError, match="no target_uuid"):
            await client.eval_expression(expression="1+1")

    async def test_eval_uses_max_text_size_4096(self, client):
        # P2.3: composite types pres options bumped from 1000 to 4096
        client.attach_debug_targets = AsyncMock(return_value=True)
        client._last_stopped_target_id = GOOD_UUID
        await client.eval_expression(expression="Контрагент")
        # Inspect the XML body that was posted — last positional arg is body
        post_call = client._post.call_args
        body = post_call.args[1] if len(post_call.args) > 1 else post_call.kwargs.get("body", "")
        assert "<debugCalculations:maxTextSize>4096</debugCalculations:maxTextSize>" in body

    async def test_eval_view_interface_opt_in(self, client):
        # P2.3: viewInterface tag included only when explicitly passed
        client.attach_debug_targets = AsyncMock(return_value=True)
        client._last_stopped_target_id = GOOD_UUID
        await client.eval_expression(
            expression="Контрагент.Ссылка", view_interface="context",
        )
        body = client._post.call_args.args[1]
        assert "<debugCalculations:viewInterface>context</debugCalculations:viewInterface>" in body

    async def test_eval_no_view_interface_by_default(self, client):
        # Default behavior — viewInterface tag absent (backward compat)
        client.attach_debug_targets = AsyncMock(return_value=True)
        client._last_stopped_target_id = GOOD_UUID
        await client.eval_expression(expression="x")
        body = client._post.call_args.args[1]
        assert "viewInterface" not in body

    async def test_eval_custom_max_text_size(self, client):
        client.attach_debug_targets = AsyncMock(return_value=True)
        client._last_stopped_target_id = GOOD_UUID
        await client.eval_expression(expression="БольшаяТаблица", max_text_size=16384)
        body = client._post.call_args.args[1]
        assert "<debugCalculations:maxTextSize>16384</debugCalculations:maxTextSize>" in body


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
        # yukon39 pattern: getDbgTargetState без id → state UI session
        root = ET.Element("root")
        ET.SubElement(root, "state").text = "Worked"
        ET.SubElement(root, "name").text = "Background server"
        client._post = AsyncMock(return_value=root)

        result = await client.get_target_state(target_uuid=None)

        client._post.assert_awaited_once()
        assert result["state"] == "Worked"
        assert result["name"] == "Background server"

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
