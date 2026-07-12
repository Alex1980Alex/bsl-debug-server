"""A6 (roadmap 260708 §8.6) unit tests: InspectWare session-state enum +
valid_next hint + correlation_id threading / persistence.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).parent.parent))

import mcp_debug_server as mds


def _client(**kw):
    base = dict(
        _attached=True,
        _user_visible_stops=set(),
        _stop_reason_by_target={},
        _recording_enabled=False,
        _known_attached_targets=set(),
        _correlation_id="corr-9",
    )
    base.update(kw)
    return SimpleNamespace(**base)


class TestSessionState:
    def test_done_when_detached(self):
        assert mds._session_state(_client(_attached=False)) == "Done"

    def test_start_when_no_stops(self):
        assert mds._session_state(_client()) == "Start"

    def test_runtime_state_on_bp_stop(self):
        c = _client(_user_visible_stops={"t1"}, _stop_reason_by_target={"t1": "breakpoint"})
        assert mds._session_state(c) == "Runtime-State"

    def test_runtime_error_on_exception_stop(self):
        c = _client(_user_visible_stops={"t1"}, _stop_reason_by_target={"t1": "exception"})
        assert mds._session_state(c) == "Runtime-Error"

    def test_exception_wins_over_bp(self):
        c = _client(
            _user_visible_stops={"t1", "t2"},
            _stop_reason_by_target={"t1": "breakpoint", "t2": "exception"},
        )
        assert mds._session_state(c) == "Runtime-Error"

    def test_post_mortem_when_recording_no_targets(self):
        c = _client(_recording_enabled=True, _known_attached_targets=set())
        assert mds._session_state(c) == "Post-Mortem"

    def test_recording_with_targets_is_start(self):
        c = _client(_recording_enabled=True, _known_attached_targets={"t1"})
        assert mds._session_state(c) == "Start"


class TestStateHint:
    def test_shape_and_valid_next(self):
        hint = mds._state_hint(_client())
        assert hint["session_state"] == "Start"
        assert "debug_set_breakpoint" in hint["valid_next"]
        assert hint["correlation_id"] == "corr-9"

    def test_runtime_state_valid_next(self):
        c = _client(_user_visible_stops={"t1"}, _stop_reason_by_target={"t1": "breakpoint"})
        hint = mds._state_hint(c)
        assert "debug_inspect_frame" in hint["valid_next"]
        assert "debug_set_variable" in hint["valid_next"]

    def test_done_valid_next(self):
        hint = mds._state_hint(_client(_attached=False))
        assert hint["valid_next"] == ["debug_connect", "debug_health_check"]


class TestCorrelationPersistence:
    def test_persist_includes_correlation(self, tmp_path, monkeypatch):
        # Redirect the active-session path into tmp and persist a client.
        path = str(tmp_path / ".active.json")
        monkeypatch.setattr(mds, "_ACTIVE_SESSION_PATH", path)
        client = SimpleNamespace(
            _attached=True,
            _registered=True,
            session_id="sid-1",
            debug_url="http://localhost:1550",
            infobase_alias="MFM",
            _line_offsets={},
            _correlation_id="corr-xyz",
        )
        mds._persist_active_session(client)
        loaded = mds._load_active_session()
        assert loaded["correlation_id"] == "corr-xyz"
