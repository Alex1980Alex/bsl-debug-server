"""Shared pytest fixtures for the 1С debug-server test suite.

M-9 (audit 260710, closed 2026-07-12): isolate the persisted `.active.json`
HMR-session file into a per-test tmp path. Without this, any test that exercises
attach/persist writes a bogus session into the real
`data/debug_sessions/.active.json`, corrupting a live HMR session on the dev
machine. Tests that need their own path still monkeypatch `_ACTIVE_SESSION_PATH`
inside the test body — that runs after this autouse fixture, so it wins.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture(autouse=True)
def _isolate_active_session(monkeypatch, tmp_path):
    """Redirect the module-global active-session path to a tmp file for every test."""
    try:
        import mcp_debug_server as mds
    except Exception:
        # A pure-helper test module that never imports the server — nothing to isolate.
        return
    monkeypatch.setattr(
        mds, "_ACTIVE_SESSION_PATH", str(tmp_path / ".active.json"), raising=False
    )
