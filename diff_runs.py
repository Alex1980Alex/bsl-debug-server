"""A4 roadmap 260708 §8.7: differential debugging over two recorded runs.

`debug_session_diff` (P2.A) already diffs session SUMMARIES (metric deltas →
regression_indicators). What was missing is STATE-level: "at line 200 in the ok
run `Скидка=10`, in the fail run `Скидка=0`". This module provides the pure
alignment + divergence logic over two snapshot streams (recorded via
`debug_session_record(capture_variables=True, label=...)`), so it is fully
unit-testable without RDBG.

Alignment key: `(module_fqn, line, hit_index_per_location)` — the Nth time
execution stops at a given (module, line). `first_divergence` reports the FIRST
point the two runs diverge, either:
- `flow`  — the stop sequences differ at a position (a branch taken in one run
  and not the other — often the bug itself), or
- `state` — the flow matches but a watched variable's value differs.
"""
from __future__ import annotations


def _norm(v) -> str:
    return "" if v is None else str(v).strip()


def stop_key(entry: dict) -> tuple:
    """(module_fqn, line) of a snapshot's innermost frame.

    RDBG callStack is outermost-first → the innermost (current) frame is the LAST
    element. Falls back to raw moduleID objectID when resolved_source is absent.
    """
    stack = entry.get("stack") or []
    innermost = stack[-1] if stack and isinstance(stack[-1], dict) else {}
    rs = innermost.get("resolved_source") if isinstance(innermost.get("resolved_source"), dict) else {}
    fqn = rs.get("fqn")
    if not fqn:
        mod = innermost.get("moduleID") if isinstance(innermost.get("moduleID"), dict) else {}
        fqn = mod.get("objectID", "") or ""
    return (fqn, innermost.get("lineNo"))


def build_sequence(entries: list) -> list:
    """Assign a per-location hit_index → [{key:(fqn,line,hit_index), entry}]."""
    counts: dict = {}
    out: list = []
    for e in entries:
        base = stop_key(e)
        idx = counts.get(base, 0)
        counts[base] = idx + 1
        out.append({"key": (base[0], base[1], idx), "entry": e})
    return out


def _lookup_ci(variables, name: str):
    """Case-insensitive local lookup in a snapshot's captured variables."""
    if not isinstance(variables, dict):
        return None
    low = name.lower()
    for k, v in variables.items():
        if str(k).lower() == low:
            return v
    return None


def align(ok_seq: list, fail_seq: list) -> list:
    """Union of stop keys (ok order first, then fail-only) → [{key, ok, fail}]."""
    ok_by = {s["key"]: s["entry"] for s in ok_seq}
    fail_by = {s["key"]: s["entry"] for s in fail_seq}
    order: list = []
    seen: set = set()
    for s in ok_seq + fail_seq:
        if s["key"] not in seen:
            seen.add(s["key"])
            order.append(s["key"])
    return [{"key": k, "ok": ok_by.get(k), "fail": fail_by.get(k)} for k in order]


def first_divergence(ok_seq: list, fail_seq: list, watch: list, ignore_names=()) -> dict | None:
    """First flow OR state divergence between two stop sequences.

    Flow first (a differing stop-key at aligned position i, or one run being
    longer), then state (same flow, a watched value differs at an aligned stop).
    Returns a divergence dict or None if the runs are identical on flow + watch.
    """
    ignore = {n.lower() for n in (ignore_names or ())}
    n = min(len(ok_seq), len(fail_seq))
    for i in range(n):
        if ok_seq[i]["key"] != fail_seq[i]["key"]:
            return {
                "kind": "flow",
                "position": i,
                "ok_key": list(ok_seq[i]["key"]),
                "fail_key": list(fail_seq[i]["key"]),
            }
    if len(ok_seq) != len(fail_seq):
        longer = "ok" if len(ok_seq) > len(fail_seq) else "fail"
        extra = (ok_seq if longer == "ok" else fail_seq)[n]["key"]
        return {"kind": "flow", "position": n, "present_in": longer, "key": list(extra)}
    for i in range(n):
        okv = ok_seq[i]["entry"].get("variables")
        fav = fail_seq[i]["entry"].get("variables")
        for w in watch or []:
            if w.lower() in ignore:
                continue
            ov = _lookup_ci(okv, w)
            fv = _lookup_ci(fav, w)
            if _norm(ov) != _norm(fv):
                return {
                    "kind": "state",
                    "position": i,
                    "location": list(ok_seq[i]["key"]),
                    "watch": w,
                    "ok": ov,
                    "fail": fv,
                }
    return None


def state_diffs(aligned: list, watch: list, ignore_names=(), max_stops: int = 200) -> list:
    """All per-aligned-stop watched-value differences (bounded, ignore-filtered)."""
    ignore = {n.lower() for n in (ignore_names or ())}
    out: list = []
    for a in aligned[:max_stops]:
        ok_e = a.get("ok")
        fail_e = a.get("fail")
        ok_vars = ok_e.get("variables") if isinstance(ok_e, dict) else None
        fail_vars = fail_e.get("variables") if isinstance(fail_e, dict) else None
        row_diffs: dict = {}
        for w in watch or []:
            if w.lower() in ignore:
                continue
            ov = _lookup_ci(ok_vars, w)
            fv = _lookup_ci(fail_vars, w)
            if _norm(ov) != _norm(fv):
                row_diffs[w] = {"ok": ov, "fail": fv}
        if row_diffs or ok_e is None or fail_e is None:
            out.append(
                {
                    "key": list(a["key"]),
                    "present": ("both" if ok_e and fail_e else ("ok" if ok_e else "fail")),
                    "diffs": row_diffs,
                }
            )
    return out
