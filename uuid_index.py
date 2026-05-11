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
"""

from __future__ import annotations

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

# Default location relative to repo root — override via env var or arg.
DEFAULT_CONFIG_SRC = Path(
    r"C:\1С-Framework\ИБTransportManagementDevelop\Конфигурация\src"
)
CACHE_PATH = Path(r"C:\1С-Framework\cache\edt_uuid_index.json")

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
        # uuid (lowercase) → {"mdo": str, "name": str, "kind": str, "child_kind": str|None}
        self._index: Optional[dict[str, dict]] = None
        self._index_mtime: Optional[float] = None

    def _src_mtime(self) -> Optional[float]:
        """Coarse mtime fingerprint — top-level src/ dir change time."""
        try:
            return self.config_src.stat().st_mtime
        except OSError:
            return None

    def _load_cache(self) -> Optional[dict[str, dict]]:
        if not self.cache_path.exists():
            return None
        try:
            data = json.loads(self.cache_path.read_text(encoding="utf-8"))
            if data.get("src_mtime") != self._src_mtime():
                log.debug("UUID cache stale (mtime mismatch), rebuilding")
                return None
            return data.get("entries")
        except (OSError, json.JSONDecodeError, KeyError) as e:
            log.debug("UUID cache load failed (%s), rebuilding", e)
            return None

    def _save_cache(self, entries: dict[str, dict]) -> None:
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(
                json.dumps(
                    {"src_mtime": self._src_mtime(), "entries": entries},
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
        except OSError as e:
            log.warning("UUID cache save failed (%s); will rebuild next run", e)

    def _scan(self) -> dict[str, dict]:
        """Cold scan all .mdo files; returns entries dict."""
        if not self.config_src.exists():
            log.warning("Config src not found: %s — UUID index will be empty",
                        self.config_src)
            return {}
        entries: dict[str, dict] = {}
        for mdo in self.config_src.rglob("*.mdo"):
            try:
                text = mdo.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            m = _ROOT_RE.search(text)
            if not m:
                continue
            root_kind, root_uuid = m.group(1), m.group(2).lower()
            try:
                rel_mdo = str(mdo.relative_to(self.config_src))
            except ValueError:
                rel_mdo = str(mdo)
            entries[root_uuid] = {
                "mdo": rel_mdo,
                "name": mdo.stem,
                "kind": root_kind,
                "child_kind": None,
            }
            for cm in _CHILD_RE.finditer(text):
                child_kind = cm.group(1).lower()
                child_uuid = cm.group(2).lower()
                child_name = cm.group(3)
                entries[child_uuid] = {
                    "mdo": rel_mdo,
                    "name": child_name,
                    "kind": root_kind,
                    "child_kind": child_kind,
                }
        log.info("UUID index built: %d entries from %s", len(entries), self.config_src)
        return entries

    def _ensure_index(self) -> dict[str, dict]:
        if self._index is not None:
            return self._index
        with self._lock:
            if self._index is not None:
                return self._index
            cached = self._load_cache()
            if cached is not None:
                self._index = cached
                log.debug("UUID index loaded from cache (%d entries)", len(cached))
                return self._index
            entries = self._scan()
            self._index = entries
            self._save_cache(entries)
            return self._index

    def reset(self) -> None:
        """Force re-scan on next lookup (e.g. after `git pull`)."""
        with self._lock:
            self._index = None
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
        mdo_path = self.config_src / rec["mdo"]
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

    def get_source_info(self, object_id: str, property_id: str) -> Optional[dict]:
        """P0.C: return {fqn, file_path, exists} for (oid, pid). None if unknown."""
        rec = self.lookup(object_id)
        if not rec:
            return None
        path = self.resolve(object_id, property_id)
        kind_ru = _KIND_FQN.get((rec.get("kind") or "").lower(), rec.get("kind", ""))
        if rec.get("child_kind") == "forms":
            fqn = f"{kind_ru}.{Path(rec['mdo']).parent.name}.Форма.{rec['name']}"
        elif rec.get("child_kind") == "commands":
            fqn = f"{kind_ru}.{Path(rec['mdo']).parent.name}.Команда.{rec['name']}"
        else:
            suffix = _PROP_FQN.get((property_id or "").lower(), "")
            fqn = f"{kind_ru}.{rec['name']}" + (f".{suffix}" if suffix else "")
        try:
            rel_path = str(path.relative_to(self.config_src)) if path else None
        except (ValueError, AttributeError):
            rel_path = str(path) if path else None
        return {
            "fqn": fqn,
            "file_path": rel_path,
            "exists": bool(path and path.exists()),
        }


# Singleton convenience for in-process callers
_default: Optional[UUIDIndex] = None


def get_default_index() -> UUIDIndex:
    global _default
    if _default is None:
        # Honor env override for test/dev configurations
        src_env = os.environ.get("BSL_DEBUG_CONFIG_SRC")
        _default = UUIDIndex(config_src=Path(src_env) if src_env else None)
    return _default


def resolve_uuid(object_id: str, property_id: str) -> Optional[Path]:
    """Module-level convenience — uses default singleton index."""
    return get_default_index().resolve(object_id, property_id)


def get_source_info(object_id: str, property_id: str) -> Optional[dict]:
    """P0.C roadmap 260511: convenience wrapper around UUIDIndex.get_source_info."""
    return get_default_index().get_source_info(object_id, property_id)
