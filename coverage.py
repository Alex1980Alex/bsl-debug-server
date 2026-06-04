"""P1.A roadmap 260511: BSL code coverage tracking via wrapper-side BP-counters.

Closes Gap 1 (code path coverage). Each tracked line registers as a silent
coverage BP — on fire, wrapper increments hit counter + auto-Continues, no
user-visible halt, no JSONL noise (distinct from P0.B logpoint behavior).

Export: SonarQube genericCoverage.xml (https://docs.sonarsource.com/sonarqube-server/latest/analyzing-source-code/test-coverage/generic-test-data/).
"""
from __future__ import annotations

import logging
from collections import defaultdict
from pathlib import Path
from xml.sax.saxutils import escape

log = logging.getLogger("1c-debug-mcp.coverage")


def register_line(client, object_id, property_id, line, file_path=""):
    """Mark (oid, pid, line) as coverage-tracked. Idempotent."""
    key = (object_id, property_id, int(line))
    if not hasattr(client, "_coverage_tracked"):
        client._coverage_tracked = {}
    client._coverage_tracked.setdefault(key, {"hits": 0, "file_path": file_path})


async def record_hit_and_continue(client, target_id, stack) -> bool:
    """If top frame matches a tracked line — increment hit + auto-Continue.

    Returns True iff suppressed (counted + Continue'd). False if not tracked.
    """
    tracked = getattr(client, "_coverage_tracked", None)
    if not tracked:
        return False
    top = stack[0] if isinstance(stack, list) and stack else None
    if not isinstance(top, dict):
        return False
    mod = top.get("moduleID") if isinstance(top.get("moduleID"), dict) else {}
    try:
        line = int(top.get("lineNo", 0))
    except (TypeError, ValueError):
        return False
    key = (mod.get("objectID", ""), mod.get("propertyID", ""), line)
    if key not in tracked:
        return False
    tracked[key]["hits"] += 1
    try:
        await client.step("Continue", target_id)
    except Exception as e:
        log.warning("[P1.A] coverage auto-Continue failed: %s", e)
        return False
    return True


def export_generic_coverage_xml(client, output_path: str) -> dict:
    """Emit SonarQube genericCoverage.xml. Returns {path, files_count, lines_total, lines_covered}."""
    tracked = getattr(client, "_coverage_tracked", {}) or {}
    by_file = defaultdict(list)  # file_path -> [(line, hits)]
    for (oid, pid, line), state in tracked.items():
        fp = state.get("file_path") or _fallback_path(oid, pid)
        by_file[fp].append((line, state["hits"]))
    lines_total = sum(len(v) for v in by_file.values())
    lines_covered = sum(1 for v in by_file.values() for (_, h) in v if h > 0)
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        f.write('<coverage version="1">\n')
        for fp in sorted(by_file.keys()):
            f.write(f'  <file path="{escape(fp)}">\n')
            for line, hits in sorted(by_file[fp]):
                covered = "true" if hits > 0 else "false"
                f.write(f'    <lineToCover lineNumber="{line}" covered="{covered}"/>\n')
            f.write("  </file>\n")
        f.write("</coverage>\n")
    return {
        "path": str(out),
        "files_count": len(by_file),
        "lines_total": lines_total,
        "lines_covered": lines_covered,
        "coverage_pct": round(100.0 * lines_covered / lines_total, 2) if lines_total else 0.0,
    }


def _fallback_path(object_id, property_id):
    return f"<unknown>/{object_id[:8]}_{property_id[:8]}.bsl"
