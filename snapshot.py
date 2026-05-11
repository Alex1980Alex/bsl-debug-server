"""P2.A roadmap 260511: snapshot recording + replay seek.

NOT true time-travel (RDBG can't rewind rphost execution). What this provides:
- Record state on each stop event (timestamp, target, stack, exception, reason)
  into `data/debug_replays/<session_id>.jsonl`
- `replay_seek(index)` returns the indexed snapshot for post-mortem inspection
- `replay_list()` returns summary of all snapshots

ROI: GKSTCPLK-2468 «не смогли воспроизвести» — snapshot replay allows
reconstructing past stops without re-running the failing scenario.
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path

log = logging.getLogger("1c-debug-mcp.snapshot")


def record(client, target_id: str, reason: str, stack: list, exc_info: dict | None = None):
    """Append a snapshot entry to the session's replay JSONL."""
    if not getattr(client, "_recording_enabled", False):
        return
    session_id = getattr(client, "session_id", None) or "unknown"
    replay_dir = Path(__file__).parent / "data" / "debug_replays"
    try:
        replay_dir.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        log.warning("[P2.A] replay dir create failed: %s", e)
        return
    entry = {
        "ts": time.time(),
        "iso": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()),
        "session_id": session_id,
        "target_id": target_id,
        "reason": reason,
        "stack": stack,
        "exception": exc_info,
    }
    path = replay_dir / f"{session_id}.jsonl"
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as e:
        log.warning("[P2.A] snapshot write failed: %s", e)


def list_snapshots(session_id: str) -> list:
    """Read replay JSONL → return list of summary dicts."""
    if not session_id:
        return []
    path = Path(__file__).parent / "data" / "debug_replays" / f"{session_id}.jsonl"
    if not path.exists():
        return []
    out = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                top = (e.get("stack") or [{}])[0]
                if not isinstance(top, dict):
                    top = {}
                out.append({
                    "index": idx,
                    "iso": e.get("iso", ""),
                    "target_id": (e.get("target_id") or "")[:8],
                    "reason": e.get("reason", ""),
                    "line": top.get("lineNo", ""),
                    "has_exception": bool(e.get("exception")),
                })
    except Exception as e:
        log.warning("[P2.A] list_snapshots read failed: %s", e)
    return out


def seek_snapshot(session_id: str, index: int) -> dict | None:
    """Read replay JSONL → return Nth snapshot (full entry). None if out of range."""
    if not session_id:
        return None
    path = Path(__file__).parent / "data" / "debug_replays" / f"{session_id}.jsonl"
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f):
                if idx != index:
                    continue
                line = line.strip()
                if not line:
                    return None
                return json.loads(line)
    except Exception as e:
        log.warning("[P2.A] seek_snapshot read failed: %s", e)
    return None
