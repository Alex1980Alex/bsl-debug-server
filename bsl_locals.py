"""Extract names of locals visible at a given line in a BSL module.

Strategy (regex-based — BSL syntax is regular enough):
1. Find module-level `Перем X, Y, Z;` declarations (visible everywhere in module)
2. Find the function/procedure containing `target_line`
3. Inside that function, collect:
   - parameter names from signature
   - `Перем X, Y;` local declarations (anywhere in body — BSL doesn't require pre-declaration)
   - first-assignment names `Имя = ...;` up to `target_line`
4. Deduplicate, return as list of strings.

BSL keywords matched: both Russian (Процедура/Функция/Перем/Знач/КонецПроцедуры/
КонецФункции) and English (Procedure/Function/Var/Val/EndProcedure/EndFunction).

Limitations:
- Conditional `#Если ... #КонецЕсли`: extractor includes ALL branches
  (RDBG returns errors for inactive vars, harmless)
- Compound assignments (`СтруктураX.Поле = ...`): excluded — not a local
- `Для X = ... Цикл`: X is a local (added to assignments)
- `Для Каждого X Из ... Цикл`: X is a local (added)
- Variables created via `Выполнить("...")`: not detectable, out of scope
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Optional

log = logging.getLogger("1c-debug-mcp.bsl-locals")

# Identifier: Cyrillic and Latin letters + digits + underscore (no leading digit).
# BSL is case-INSENSITIVE for identifiers but we preserve case as written.
_IDENT = r"[A-Za-zА-Яа-яЁё_][A-Za-zА-Яа-яЁё_0-9]*"

# Module-level Перем (only at top, before any Процедура/Функция).
# Matches `Перем X, Y, Z Экспорт;` or `Var X, Y;`. Captures the names group.
_MODULE_VAR_RE = re.compile(
    rf"^\s*(?:Перем|Var)\s+([^;]+?)(?:\s+(?:Экспорт|Export))?\s*;",
    re.IGNORECASE | re.MULTILINE,
)

# Function/procedure declaration: capture name + params + start line offset.
# Both Russian and English keywords. Group 1=kind, group 2=name, group 3=raw params.
_FUNC_DECL_RE = re.compile(
    rf"^\s*(Процедура|Функция|Procedure|Function)\s+({_IDENT})\s*\(([^)]*)\)",
    re.IGNORECASE | re.MULTILINE,
)
_FUNC_END_RE = re.compile(
    r"^\s*(?:КонецПроцедуры|КонецФункции|EndProcedure|EndFunction)\b",
    re.IGNORECASE | re.MULTILINE,
)

# Local Перем inside function body
_LOCAL_VAR_RE = re.compile(
    rf"^\s*(?:Перем|Var)\s+([^;]+?)\s*;",
    re.IGNORECASE | re.MULTILINE,
)

# Assignment LHS: `Имя = ...;` at line start (after possible whitespace).
# Excludes property assignments (`X.Y = ...`) and indexed (`X[i] = ...`).
_ASSIGN_RE = re.compile(
    rf"^\s*({_IDENT})\s*=\s*[^=]",
    re.MULTILINE,
)

# `Для X = ... Цикл` and `Для Каждого X Из ... Цикл` — X is loop variable
_FOR_RE = re.compile(
    rf"^\s*(?:Для|For)(?:\s+(?:Каждого|Each))?\s+({_IDENT})\b",
    re.IGNORECASE | re.MULTILINE,
)


def _split_var_list(raw: str) -> list[str]:
    """Parse comma-separated var name list, stripping `Экспорт` and whitespace."""
    out = []
    for token in raw.split(","):
        token = token.strip()
        # Drop trailing Экспорт/Export modifier (only valid at module level)
        token = re.sub(r"\s+(?:Экспорт|Export)\s*$", "", token, flags=re.IGNORECASE)
        if re.fullmatch(_IDENT, token):
            out.append(token)
    return out


def _parse_params(raw: str) -> list[str]:
    """Extract parameter names from raw `(...)` content.

    Handles `Знач Имя`, `Имя = ЗначениеПоУмолчанию`, multiple params separated
    by commas at top level (defaults may contain commas inside structures —
    BSL syntax doesn't allow that for default values, so simple split is safe).
    """
    out = []
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        # Strip leading Знач/Val
        chunk = re.sub(r"^(?:Знач|Val)\s+", "", chunk, flags=re.IGNORECASE)
        # Take everything before `=` (default value separator)
        name = chunk.split("=", 1)[0].strip()
        if re.fullmatch(_IDENT, name):
            out.append(name)
    return out


def _function_span_at(source: str, target_line: int) -> Optional[tuple[int, int, str, str]]:
    """Find function declaration enclosing `target_line` (1-based).

    Returns (start_line, end_line, name, params_raw) or None if target_line
    is at module top (between functions / before any function).
    """
    # Compute line offsets — index by 0-based char position
    line_starts = [0]
    for i, ch in enumerate(source):
        if ch == "\n":
            line_starts.append(i + 1)

    def offset_to_line(offset: int) -> int:
        # Binary search would be faster, but BSL files are small
        for ln, start in enumerate(line_starts, 1):
            if start > offset:
                return ln - 1
        return len(line_starts)

    # Iterate function declarations + their matching ends
    decls = list(_FUNC_DECL_RE.finditer(source))
    ends = list(_FUNC_END_RE.finditer(source))
    for decl in decls:
        decl_line = offset_to_line(decl.start())
        # Find first end after this decl
        end_offset = None
        for e in ends:
            if e.start() > decl.start():
                end_offset = e.end()
                break
        if end_offset is None:
            continue
        end_line = offset_to_line(end_offset)
        if decl_line <= target_line <= end_line:
            return decl_line, end_line, decl.group(2), decl.group(3)
    return None


def extract_locals_at_line(source_path: Path, target_line: int) -> list[str]:
    """Extract names of all locals visible at `target_line` in `source_path`.

    Returns ordered, deduplicated list of identifiers. Empty list on errors
    (file unreadable, no enclosing function, etc.) — caller handles fallback.
    """
    try:
        source = source_path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError as e:
        log.warning("Cannot read %s: %s", source_path, e)
        return []

    names: list[str] = []
    seen: set[str] = set()

    def add(n: str) -> None:
        # BSL identifiers are case-insensitive; dedupe case-insensitively
        # but preserve the first-seen case for display.
        key = n.lower()
        if key not in seen:
            seen.add(key)
            names.append(n)

    # 1. Module-level Перем (visible everywhere) — only above first function
    first_decl = _FUNC_DECL_RE.search(source)
    head_end = first_decl.start() if first_decl else len(source)
    head = source[:head_end]
    for m in _MODULE_VAR_RE.finditer(head):
        for name in _split_var_list(m.group(1)):
            add(name)

    # 2. Enclosing function — params + locals up to target_line
    fn = _function_span_at(source, target_line)
    if fn is None:
        # target_line outside any function — only module vars apply
        return names
    decl_line, end_line, fn_name, params_raw = fn
    for name in _parse_params(params_raw):
        add(name)

    # Slice function body up to and including target_line for partial scan.
    # Keep full body to also pick up Перем declared after target_line — those
    # are visible (BSL is hoisted: Перем declarations are scope-wide).
    body_start_offset = sum(1 for _ in source[:0])  # 0
    # Compute char offsets for decl_line and end_line bounds
    line_starts = [0]
    for i, ch in enumerate(source):
        if ch == "\n":
            line_starts.append(i + 1)

    def line_to_offset(ln: int) -> int:
        return line_starts[ln - 1] if 1 <= ln <= len(line_starts) else len(source)

    body_offset = line_to_offset(decl_line)
    body_end_offset = line_to_offset(end_line + 1) if end_line + 1 <= len(line_starts) else len(source)
    body = source[body_offset:body_end_offset]

    # All Перем declarations inside function (hoisted to function scope)
    for m in _LOCAL_VAR_RE.finditer(body):
        for name in _split_var_list(m.group(1)):
            add(name)

    # Assignment LHS up to and INCLUDING target_line (assignment on the stop
    # line is considered in-scope for inspection — even if RDBG technically
    # hasn't bound the value yet, the user expects to see it).
    target_offset_in_body = line_to_offset(target_line + 1) - body_offset
    body_up_to_target = body[: max(0, target_offset_in_body)]
    for m in _ASSIGN_RE.finditer(body_up_to_target):
        add(m.group(1))
    for m in _FOR_RE.finditer(body_up_to_target):
        add(m.group(1))

    return names
