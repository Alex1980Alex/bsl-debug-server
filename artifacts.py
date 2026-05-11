"""P1.B roadmap 260511: package debug session artifacts as ZIP bundle.

For CI/PR review: collect summary.json + summary.md + breakpoints + stop events
+ logpoint JSONL + last stack snapshots into a single ZIP for upload as PR
artifact.

Closes Gap 2 (regression detection через structured metrics shared via PR).
"""
from __future__ import annotations

import json
import logging
import zipfile
from pathlib import Path

log = logging.getLogger("1c-debug-mcp.artifacts")


def build_session_zip(client, summary: dict, render_md_fn) -> dict:
    """Package session artifacts into ZIP. Returns {path, size, files[]}."""
    session_id = summary.get("session_id") or "unknown"
    out_dir = Path(__file__).parent / "data" / "debug_artifacts"
    out_dir.mkdir(parents=True, exist_ok=True)
    zip_path = out_dir / f"{session_id}.zip"
    files_written = []
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        _write(zf, "summary.json", json.dumps(summary, ensure_ascii=False, indent=2),
               files_written)
        try:
            md = render_md_fn(summary)
        except Exception as e:
            log.warning("[P1.B] markdown render failed: %s", e)
            md = f"# Debug session {session_id[:8]}\n_(markdown render failed)_"
        _write(zf, "summary.md", md, files_written)
        _write(zf, "breakpoints_cache.json",
               json.dumps(getattr(client, "_set_breakpoints_cache", []),
                          ensure_ascii=False, indent=2),
               files_written)
        _write(zf, "stop_events.json",
               json.dumps(list(getattr(client, "_stop_events", [])),
                          ensure_ascii=False, indent=2),
               files_written)
        _maybe_attach_logpoint_jsonl(zf, client, session_id, files_written)
        _attach_stack_snapshots(zf, client, files_written)
    return {
        "path": str(zip_path),
        "size_bytes": zip_path.stat().st_size,
        "files": files_written,
    }


def _write(zf, name, content, files_written):
    zf.writestr(name, content)
    files_written.append(name)


def _maybe_attach_logpoint_jsonl(zf, client, session_id, files_written):
    log_dir = getattr(client, "_log_dir", None)
    if log_dir is None:
        return
    log_file = Path(log_dir) / f"{session_id}.jsonl"
    if not log_file.exists():
        return
    try:
        _write(zf, "logpoint_log.jsonl",
               log_file.read_text(encoding="utf-8"), files_written)
    except Exception as e:
        log.warning("[P1.B] logpoint JSONL attach failed: %s", e)


def _attach_stack_snapshots(zf, client, files_written):
    stacks = getattr(client, "_last_stack_by_target", {}) or {}
    for tid, stack in stacks.items():
        try:
            _write(zf, f"stack_snapshots/{tid}.json",
                   json.dumps(stack, ensure_ascii=False, indent=2), files_written)
        except Exception as e:
            log.warning("[P1.B] stack snapshot %s failed: %s", tid[:8], e)
