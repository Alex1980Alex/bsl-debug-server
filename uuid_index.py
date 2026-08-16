"""RDBG objectID UUID → BSL source path resolver.

EDT exports configuration to `<EDT-project>/Конфигурация/src/<TopType>/<ObjectName>/`
with `<ObjectName>.mdo` manifest containing the root object's UUID, plus nested
`<forms uuid="...">` / `<commands uuid="...">` for sub-modules.

Verified 2026-05-10 against `Documents/гкс_ЛабораторныйАнализ/гкс_ЛабораторныйАнализ.mdo`:
- Root <document uuid="X"> → Document.ObjectModule / ManagerModule / etc
- <forms uuid="Y"><name>ФормаСписка</name> → Forms/ФормаСписка/Module.bsl
- <commands uuid="Z"><name>...</name> → Commands/<Name>/CommandModule.bsl

Performance: ~0.4s cold scan of 2541 MDO files → ~7848 UUIDs (~1.5MB RAM).
Lazy-build at first call, optional disk cache by `src/` mtime.

Extensions (W5, 2026-08-12): an EDT workspace holds the main project at
`<ws>/Конфигурация/src` plus sibling extension projects at
`<ws>/Конфигурация.<ExtName>/src`. RDBG addresses extension modules by
objectID + extensionName — a BP without extensionName lands in the main
config namespace and silently never fires. The index therefore scans all
sibling extension roots too, tags their entries with `extension`, and
exposes `extension_of()` so the debug server can auto-fill extensionName.
On a UUID collision the MAIN config wins. Note (review 260812): in live EDT
exports adopted objects carry their OWN uuid plus extendedConfigurationObject
(not the base uuid), so cross-root collisions are a defensive edge case, not
the norm; main-first simply guarantees pre-W5 behaviour for main-config BPs.
Misattribution escape hatch: pass extension_name="" to the debug server's
set_breakpoints/debug_set_breakpoint to force the main-config namespace.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
from pathlib import Path
from typing import Optional

log = logging.getLogger("1c-debug-mcp.uuid-index")

# propertyID UUID → (BSL filename within object dir, child folder kind)
# Mirrors MODULE_PROPERTY_IDS in mcp_debug_server.py — duplicated to keep
# this module standalone (importable without touching the main server).
MODULE_PROPERTY_FILES: dict[str, tuple[str, Optional[str]]] = {
    "d5963243-262e-4398-b4d7-fb16d06484f6": ("Module.bsl", None),         # CommonModule
    "d1b64a2c-8078-4982-8190-8f81aefda192": ("ManagerModule.bsl", None),  # ManagerModule
    "a637f77f-3840-441d-a1c3-699c8c5cb7e0": ("ObjectModule.bsl", None),   # ObjectModule
    "9f36fd70-4bf4-47f6-b235-935f73aab43f": ("ManagerModule.bsl", None),  # RecordSetModule → MgrModule
    "32e087ab-1491-49b6-aba7-43571b41ac2b": ("Module.bsl", "Forms"),      # FormModule
    "078a6af8-d22c-4248-9c33-7e90075a3d2c": ("CommandModule.bsl", "Commands"),
}

# P0.C roadmap 260511: kind (mdo root tag) → Russian FQN prefix
_KIND_FQN = {
    "document": "Документ", "catalog": "Справочник",
    "informationregister": "РегистрСведений",
    "accumulationregister": "РегистрНакопления",
    "accountingregister": "РегистрБухгалтерии",
    "calculationregister": "РегистрРасчёта",
    "chartofcharacteristictypes": "ПланВидовХарактеристик",
    "chartofaccounts": "ПланСчетов",
    "chartofcalculationtypes": "ПланВидовРасчёта",
    "businessprocess": "БизнесПроцесс", "task": "Задача",
    "exchangeplan": "ПланОбмена", "enum": "Перечисление",
    "report": "Отчёт", "dataprocessor": "Обработка",
    "commonmodule": "ОбщийМодуль", "subsystem": "Подсистема",
}
# propertyID → Russian module-kind suffix
_PROP_FQN = {
    "d1b64a2c-8078-4982-8190-8f81aefda192": "МодульМенеджера",
    "a637f77f-3840-441d-a1c3-699c8c5cb7e0": "МодульОбъекта",
    "9f36fd70-4bf4-47f6-b235-935f73aab43f": "МодульНабораЗаписей",
    "32e087ab-1491-49b6-aba7-43571b41ac2b": "МодульФормы",
    "078a6af8-d22c-4248-9c33-7e90075a3d2c": "МодульКоманды",
    "d5963243-262e-4398-b4d7-fb16d06484f6": "",  # CommonModule whole-module
}

# C2 en-fqn (re-audit 260712): English metadata-class prefixes, so
# find_by_fqn also resolves the EN form ("Document.X.ObjectModule",
# "CommonModule.Y") — the RU-only reverse map used to return None for them.
_KIND_FQN_EN = {
    "document": "Document", "catalog": "Catalog",
    "informationregister": "InformationRegister",
    "accumulationregister": "AccumulationRegister",
    "accountingregister": "AccountingRegister",
    "calculationregister": "CalculationRegister",
    "chartofcharacteristictypes": "ChartOfCharacteristicTypes",
    "chartofaccounts": "ChartOfAccounts",
    "chartofcalculationtypes": "ChartOfCalculationTypes",
    "businessprocess": "BusinessProcess", "task": "Task",
    "exchangeplan": "ExchangePlan", "enum": "Enum",
    "report": "Report", "dataprocessor": "DataProcessor",
    "commonmodule": "CommonModule", "subsystem": "Subsystem",
}

# Default location relative to repo root — override via env var or arg.
DEFAULT_CONFIG_SRC = Path(
    r"C:\1С-Framework\ИБTransportManagementDevelop\Конфигурация\src"
)
CACHE_PATH = Path(r"C:\1С-Framework\cache\edt_uuid_index.json")

# W5: first <name>…</name> in an extension project's Configuration.mdo is the
# extension name as the platform knows it (= РасширенияКонфигурации.Имя).
_CONFIG_NAME_RE = re.compile(r"<name>([^<]+)</name>")


def _extension_name_of(src_root: Path) -> Optional[str]:
    """Platform extension name for an EDT extension project src root.

    Reads `src/Configuration/Configuration.mdo` <name>; falls back to the
    project dir suffix after the first dot (`Конфигурация.Foo` → `Foo`).
    """
    mdo = src_root / "Configuration" / "Configuration.mdo"
    try:
        m = _CONFIG_NAME_RE.search(mdo.read_text(encoding="utf-8", errors="ignore"))
        if m and m.group(1).strip():
            return m.group(1).strip()
    except OSError:
        pass
    parent = src_root.parent.name
    if "." in parent:
        suffix = parent.split(".", 1)[1].strip()
        return suffix or None
    return None


def _discover_extension_roots(config_src: Path) -> list[tuple[str, Path]]:
    """Sibling EDT extension projects of a main-config src root.

    `<ws>/Конфигурация/src` → every `<ws>/Конфигурация.<Ext>/src` that exists.
    Sorted for deterministic scan order; empty on any FS trouble (fail-soft —
    behaviour without extensions is exactly pre-W5).
    """
    roots: list[tuple[str, Path]] = []
    try:
        ws = config_src.parent.parent
        if not ws.exists():
            return []
        for src in sorted(ws.glob("Конфигурация.*/src")):
            if not src.is_dir():
                continue
            name = _extension_name_of(src)
            if name:
                roots.append((name, src))
    except OSError:
        return []
    return roots


# Captures: <ns:tag uuid="X"> on root — first match per file is the parent object
_ROOT_RE = re.compile(
    r'<(?:mdclass:)?(\w+)\b[^>]*\suuid="([0-9a-f-]{36})"',
    re.IGNORECASE,
)
# Captures nested <forms uuid="X"><name>FOO</name> / <commands uuid="X"><name>BAR</name>
_CHILD_RE = re.compile(
    r'<(forms|commands)\s+uuid="([0-9a-f-]{36})"\s*>\s*<name>([^<]+)</name>',
    re.IGNORECASE | re.DOTALL,
)


class UUIDIndex:
    """Thread-safe lazy-built UUID → metadata index for an EDT export."""

    def __init__(self, config_src: Optional[Path] = None,
                 cache_path: Optional[Path] = None):
        self.config_src = Path(config_src) if config_src else DEFAULT_CONFIG_SRC
        self.cache_path = Path(cache_path) if cache_path else CACHE_PATH
        self._lock = threading.Lock()
        # W5: sibling extension projects; "" key = main config root.
        self.extension_roots: list[tuple[str, Path]] = _discover_extension_roots(
            self.config_src
        )
        self._roots_by_ext: dict[str, Path] = {"": self.config_src}
        self._roots_by_ext.update(dict(self.extension_roots))
        # uuid (lowercase) → {"mdo": str, "name": str, "kind": str,
        #                     "child_kind": str|None, "extension": str (W5, ""=main)}
        self._index: Optional[dict[str, dict]] = None
        # C2 (roadmap §8.2): lazy reverse map fqn_lower → (object_id, module_type)
        self._reverse: Optional[dict] = None

    def _src_fingerprint(self) -> Optional[dict]:
        """Recursive fingerprint of the .mdo tree for cache invalidation.

        B5 (roadmap 260708 W2): the old coarse top-level dir mtime missed edits
        to NESTED .mdo files (editing a module never bumps the src/ dir mtime)
        → a stale cache was served. This walks every *.mdo and aggregates
        {max_mtime, count, total_size}: max_mtime catches content edits, count
        catches add/remove, total_size catches a same-mtime content swap.
        Stat-only (no file reads) — cheaper than the full _scan(), and it runs
        at most once per process (the result is memoised in self._index).
        """
        try:
            if not self.config_src.exists() and not self.extension_roots:
                return None
            max_mtime = 0.0
            count = 0
            total_size = 0
            for _ext, root in self._iter_roots():
                if not root.exists():
                    continue
                for mdo in root.rglob("*.mdo"):
                    try:
                        st = mdo.stat()
                    except OSError:
                        continue
                    count += 1
                    total_size += st.st_size
                    if st.st_mtime > max_mtime:
                        max_mtime = st.st_mtime
            return {
                "max_mtime": max_mtime,
                "count": count,
                "total_size": total_size,
                # W5: adding/removing an extension project invalidates the cache
                # even if its tree is empty; also invalidates every pre-W5 cache
                # (old fingerprints lack this key → strict != → rebuild).
                "roots": [f"{ext}={root}" for ext, root in self._iter_roots()],
            }
        except OSError:
            return None

    def _iter_roots(self) -> list[tuple[str, Path]]:
        """Scan order: main config first, then extensions (main wins collisions)."""
        return [("", self.config_src)] + list(self.extension_roots)

    def _load_cache(self, fingerprint: Optional[dict]) -> Optional[dict[str, dict]]:
        if not self.cache_path.exists():
            return None
        try:
            data = json.loads(self.cache_path.read_text(encoding="utf-8"))
            if data.get("src_fingerprint") != fingerprint:
                log.debug("UUID cache stale (fingerprint mismatch), rebuilding")
                return None
            return data.get("entries")
        except (OSError, json.JSONDecodeError, KeyError) as e:
            log.debug("UUID cache load failed (%s), rebuilding", e)
            return None

    def _save_cache(self, entries: dict[str, dict], fingerprint: Optional[dict]) -> None:
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(
                json.dumps(
                    {"src_fingerprint": fingerprint, "entries": entries},
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
        except OSError as e:
            log.warning("UUID cache save failed (%s); will rebuild next run", e)

    def _scan(self) -> dict[str, dict]:
        """Cold scan all .mdo files across main + extension roots.

        setdefault everywhere: main config is scanned first and WINS cross-root
        UUID collisions. Side effect (review 260812): a duplicate UUID WITHIN
        one tree now resolves first-by-rglob-order (was: last-wins). Valid EDT
        exports have no intra-tree duplicates, so this only affects corrupt
        trees — deterministic either way.
        """
        if not self.config_src.exists() and not self.extension_roots:
            log.warning("Config src not found: %s — UUID index will be empty",
                        self.config_src)
            return {}
        entries: dict[str, dict] = {}
        for ext_name, root in self._iter_roots():
            if not root.exists():
                if not ext_name:
                    log.warning("Config src not found: %s — scanning extensions only",
                                root)
                continue
            for mdo in root.rglob("*.mdo"):
                try:
                    text = mdo.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                m = _ROOT_RE.search(text)
                if not m:
                    continue
                root_kind, root_uuid = m.group(1), m.group(2).lower()
                try:
                    rel_mdo = str(mdo.relative_to(root))
                except ValueError:
                    rel_mdo = str(mdo)
                # W5: setdefault — main config scanned first and WINS a UUID
                # collision (adopted-in-extension objects may share the base
                # object's UUID; see module docstring).
                entries.setdefault(root_uuid, {
                    "mdo": rel_mdo,
                    "name": mdo.stem,
                    "kind": root_kind,
                    "child_kind": None,
                    "extension": ext_name,
                })
                for cm in _CHILD_RE.finditer(text):
                    child_kind = cm.group(1).lower()
                    child_uuid = cm.group(2).lower()
                    child_name = cm.group(3)
                    entries.setdefault(child_uuid, {
                        "mdo": rel_mdo,
                        "name": child_name,
                        "kind": root_kind,
                        "child_kind": child_kind,
                        "extension": ext_name,
                    })
        log.info("UUID index built: %d entries from %s (+%d extension roots)",
                 len(entries), self.config_src, len(self.extension_roots))
        return entries

    def _ensure_index(self) -> dict[str, dict]:
        if self._index is not None:
            return self._index
        with self._lock:
            if self._index is not None:
                return self._index
            fingerprint = self._src_fingerprint()
            cached = self._load_cache(fingerprint)
            if cached is not None:
                self._index = cached
                log.debug("UUID index loaded from cache (%d entries)", len(cached))
                return self._index
            entries = self._scan()
            self._index = entries
            self._save_cache(entries, fingerprint)
            return self._index

    def reset(self) -> None:
        """Force re-scan on next lookup (e.g. after `git pull`)."""
        with self._lock:
            self._index = None
            self._reverse = None
            try:
                self.cache_path.unlink(missing_ok=True)
            except OSError:
                pass

    def resolve(self, object_id: str, property_id: str) -> Optional[Path]:
        """Resolve (objectID, propertyID) to absolute BSL source path.

        Returns None if UUID unknown or property_id has no module mapping.
        Does NOT verify file existence — caller checks `Path.exists()`.
        """
        idx = self._ensure_index()
        rec = idx.get(object_id.lower())
        if not rec:
            return None
        file_name, child_subdir = MODULE_PROPERTY_FILES.get(
            property_id.lower(), (None, None)
        )
        if file_name is None:
            return None
        mdo_path = self._root_of(rec) / rec["mdo"]
        obj_dir = mdo_path.parent
        if rec["child_kind"] == "forms":
            # FormModule UUID is on the form itself; obj_dir is parent's dir
            return obj_dir / "Forms" / rec["name"] / "Module.bsl"
        if rec["child_kind"] == "commands":
            return obj_dir / "Commands" / rec["name"] / "CommandModule.bsl"
        # Root object UUID — append the module file by property_id
        return obj_dir / file_name

    def lookup(self, object_id: str) -> Optional[dict]:
        """Raw entry lookup (for diagnostics)."""
        idx = self._ensure_index()
        return idx.get(object_id.lower())

    def _root_of(self, rec: dict) -> Path:
        """W5: source root the entry was scanned from ("" / missing = main)."""
        return self._roots_by_ext.get(rec.get("extension", "") or "", self.config_src)

    def extension_for(self, object_id: str) -> str:
        """W5: platform extension name owning this UUID ("" = main config).

        Feeds RDBG `extensionName` in BSLModuleId — without it a BP on an
        extension module registers against the main config and never fires.
        """
        rec = self.lookup(object_id)
        return (rec or {}).get("extension", "") or ""

    def get_source_info(self, object_id: str, property_id: str) -> Optional[dict]:
        """P0.C: return {fqn, file_path, exists} for (oid, pid). None if unknown."""
        rec = self.lookup(object_id)
        if not rec:
            return None
        # Guard forms/commands branches: property_id must match the corresponding
        # module UUID (FormModule for forms, CommandModule for commands) — otherwise
        # caller passed a mismatched pair and FQN would be misleading.
        pid_l = (property_id or "").lower()
        path = self.resolve(object_id, property_id)
        kind_ru = _KIND_FQN.get((rec.get("kind") or "").lower(), rec.get("kind", ""))
        if rec.get("child_kind") == "forms":
            if pid_l != "32e087ab-1491-49b6-aba7-43571b41ac2b":
                return None
            fqn = f"{kind_ru}.{Path(rec['mdo']).parent.name}.Форма.{rec['name']}"
        elif rec.get("child_kind") == "commands":
            if pid_l != "078a6af8-d22c-4248-9c33-7e90075a3d2c":
                return None
            fqn = f"{kind_ru}.{Path(rec['mdo']).parent.name}.Команда.{rec['name']}"
        else:
            suffix = _PROP_FQN.get((property_id or "").lower(), "")
            fqn = f"{kind_ru}.{rec['name']}" + (f".{suffix}" if suffix else "")
        try:
            rel_path = str(path.relative_to(self._root_of(rec))) if path else None
        except (ValueError, AttributeError):
            rel_path = str(path) if path else None
        return {
            "fqn": fqn,
            "file_path": rel_path,
            "exists": bool(path and path.exists()),
            # W5: "" = main config; non-empty = extension owning the module
            "extension": rec.get("extension", "") or "",
        }

    def find_by_fqn(self, module_fqn: str) -> Optional[tuple]:
        """C2 (roadmap §8.2) reverse lookup: module fqn → (object_id, module_type).

        Lazily builds the reverse map on first call (cached until reset()).
        Case-insensitive; None if the fqn isn't a known module. The caller
        still verifies the resolved source file exists (invalid object/manager/
        recordset combos resolve to a path that won't exist).
        """
        if not module_fqn:
            return None
        idx = self._ensure_index()
        with self._lock:
            if self._reverse is None:
                self._reverse = _reverse_fqn_entries(idx)
            rev = self._reverse  # capture under lock — concurrent reset() nils it
        return rev.get(module_fqn.strip().lower())


# Singleton convenience for in-process callers
_default: Optional[UUIDIndex] = None


def get_default_index() -> UUIDIndex:
    global _default
    if _default is None:
        # Honor env override for test/dev configurations
        src_env = os.environ.get("BSL_DEBUG_CONFIG_SRC")
        _default = UUIDIndex(config_src=Path(src_env) if src_env else None)
    return _default


# --- B5 (roadmap 260708 W2): per-infobase config_src for portability ---
# One debug server can target different infobases (Transport / SVETLY / MFM),
# each with its own EDT export. Map infobase alias -> config src via env
# BSL_DEBUG_CONFIG_SRC_MAP="Alias1=C:\\path1;Alias2=D:\\path2" ('=' separates
# alias from path because Windows paths contain ':'). Unmapped aliases fall back
# to BSL_DEBUG_CONFIG_SRC / DEFAULT_CONFIG_SRC, so behaviour is unchanged when
# the env var is absent.
_indexes_by_alias: dict[str, UUIDIndex] = {}
_alias_lock = threading.Lock()
_active_alias: Optional[str] = None


def _parse_config_src_map() -> dict[str, Path]:
    """Parse BSL_DEBUG_CONFIG_SRC_MAP ('Alias=path;Alias=path')."""
    raw = os.environ.get("BSL_DEBUG_CONFIG_SRC_MAP", "").strip()
    mapping: dict[str, Path] = {}
    for entry in raw.split(";"):
        entry = entry.strip()
        if not entry or "=" not in entry:
            continue
        alias, _, path = entry.partition("=")
        alias, path = alias.strip(), path.strip()
        if alias and path:
            mapping[alias] = Path(path)
    return mapping


def _cache_path_for(config_src: Path) -> Path:
    """Distinct cache file per config_src so infobases don't clobber each other."""
    h = hashlib.sha1(str(config_src).encode("utf-8")).hexdigest()[:12]
    return CACHE_PATH.with_name(f"{CACHE_PATH.stem}_{h}{CACHE_PATH.suffix}")


def set_active_config(alias: Optional[str]) -> None:
    """Select which infobase's config_src the module-level resolve_uuid /
    get_source_info use by default. Called on connect / session restore -- there
    is one live RDBG connection at a time, so a module-global active alias is
    exact, not a heuristic."""
    global _active_alias
    _active_alias = alias


# W5: root under which EDT workspaces live, named by infobase alias
# (module-level so tests can monkeypatch it — review 260812).
_WORKSPACE_PARENT = DEFAULT_CONFIG_SRC.parent.parent.parent


def _workspace_candidate(alias: str) -> Optional[Path]:
    """W5: derive an EDT workspace src root from the repo convention
    `<repo>/<alias>/Конфигурация/src` (e.g. DEV_TAV_01_mss-dev1c02). Accepted
    when the main src exists OR the workspace holds extension projects —
    the latter covers workspaces where only extensions are exported.

    The alias must be a single plain path segment: `:` is rejected too
    (review 260812 — `Path(base) / "C:"` DISCARDS base on Windows, making the
    candidate CWD-dependent), as are NUL and traversal characters. 1C cluster
    infobase names never contain any of these.
    """
    if not alias or any(ch in alias for ch in ("/", "\\", ":", "\x00")) or ".." in alias:
        return None
    ws = _WORKSPACE_PARENT / alias
    candidate = ws / "Конфигурация" / "src"
    try:
        if candidate.exists() or any(ws.glob("Конфигурация.*/src")):
            return candidate
    except (OSError, ValueError):
        pass
    return None


def get_index_for_alias(alias: Optional[str]) -> UUIDIndex:
    """UUIDIndex for infobase `alias`. Resolution order: explicit
    BSL_DEBUG_CONFIG_SRC_MAP entry > repo-convention workspace autodiscovery
    (W5, `<repo>/<alias>/Конфигурация/src`) > default singleton. Mapped and
    autodiscovered aliases get dedicated indexes (own cache files)."""
    if not alias:
        return get_default_index()
    config_src = _parse_config_src_map().get(alias)
    if config_src is None:
        config_src = _workspace_candidate(alias)
    if config_src is None or config_src == DEFAULT_CONFIG_SRC:
        return get_default_index()
    key = str(config_src)
    with _alias_lock:
        idx = _indexes_by_alias.get(key)
        if idx is None:
            idx = UUIDIndex(config_src=config_src, cache_path=_cache_path_for(config_src))
            _indexes_by_alias[key] = idx
        return idx


def resolve_uuid(object_id: str, property_id: str,
                 alias: Optional[str] = None) -> Optional[Path]:
    """Module-level convenience -- routes to the active/aliased config index."""
    return get_index_for_alias(
        alias if alias is not None else _active_alias
    ).resolve(object_id, property_id)


def get_source_info(object_id: str, property_id: str,
                    alias: Optional[str] = None) -> Optional[dict]:
    """P0.C roadmap 260511: convenience wrapper (alias-aware since B5)."""
    return get_index_for_alias(
        alias if alias is not None else _active_alias
    ).get_source_info(object_id, property_id)


def extension_of(object_id: str, alias: Optional[str] = None) -> str:
    """W5: extension name owning `object_id` ("" = main config / unknown)."""
    return get_index_for_alias(
        alias if alias is not None else _active_alias
    ).extension_for(object_id)


def _reverse_fqn_entries(entries: dict) -> dict:
    """C2 (roadmap 260708 §8.2): reverse of get_source_info's fqn-builder —
    module fqn (lowercased) -> (object_id_lower, module_type), used by
    debug_set_function_breakpoint to resolve a fully-qualified BSL name back
    to the source object/module that produced it.

    Mirrors UUIDIndex.get_source_info exactly:
      - forms/commands children build "{kind_ru}.{ParentName}.Форма.{name}"
        / "{kind_ru}.{ParentName}.Команда.{name}" (module_type FormModule /
        CommandModule respectively);
      - root objects build "{kind_ru}.{Name}" for CommonModule, or the three
        object/manager/recordset combos "{kind_ru}.{Name}[.Suffix]" for
        everything else. Non-existent modules (e.g. an ObjectModule combo for
        a kind that has no object module) are simply resolved to a fqn that
        will never match a real source file — filtered out by the caller's
        existence check at resolve time, not here.

    setdefault() keeps the first writer on a (rare) fqn collision, since dict
    iteration order is insertion order and we prefer earlier entries.
    """
    rev: dict = {}
    for uuid_l, rec in entries.items():
        k = (rec.get("kind") or "").lower()
        kind_ru = _KIND_FQN.get(k, rec.get("kind", ""))
        kind_en = _KIND_FQN_EN.get(k, rec.get("kind", ""))
        child = rec.get("child_kind")
        if child == "forms":
            parent = Path(rec["mdo"]).parent.name
            # RU «Форма» + EN «Form» (re-audit 260712)
            rev.setdefault(f"{kind_ru}.{parent}.Форма.{rec['name']}".lower(), (uuid_l, "FormModule"))
            rev.setdefault(f"{kind_en}.{parent}.Form.{rec['name']}".lower(), (uuid_l, "FormModule"))
        elif child == "commands":
            parent = Path(rec["mdo"]).parent.name
            rev.setdefault(f"{kind_ru}.{parent}.Команда.{rec['name']}".lower(), (uuid_l, "CommandModule"))
            rev.setdefault(f"{kind_en}.{parent}.Command.{rec['name']}".lower(), (uuid_l, "CommandModule"))
        else:
            if k == "commonmodule":
                # (module_type, RU-suffix, EN-suffix)
                combos = [("CommonModule", "", "")]
            else:
                combos = [
                    ("ObjectModule", "МодульОбъекта", "ObjectModule"),
                    ("ManagerModule", "МодульМенеджера", "ManagerModule"),
                    ("RecordSetModule", "МодульНабораЗаписей", "RecordSetModule"),
                ]
            for module_type, ru_suffix, en_suffix in combos:
                ru_fqn = f"{kind_ru}.{rec['name']}" + (f".{ru_suffix}" if ru_suffix else "")
                en_fqn = f"{kind_en}.{rec['name']}" + (f".{en_suffix}" if en_suffix else "")
                rev.setdefault(ru_fqn.lower(), (uuid_l, module_type))
                rev.setdefault(en_fqn.lower(), (uuid_l, module_type))
    return rev


def find_by_fqn(module_fqn: str, alias: Optional[str] = None) -> Optional[tuple]:
    """C2 (roadmap §8.2) module-level convenience: module fqn -> (object_id, module_type)."""
    return get_index_for_alias(
        alias if alias is not None else _active_alias
    ).find_by_fqn(module_fqn)
