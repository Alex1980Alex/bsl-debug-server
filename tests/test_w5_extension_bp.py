"""W5 (2026-08-12): extension-module breakpoints.

Covers the two root causes of «BP в модуле расширения молчит»:
1. uuid_index was single-root — extension sources unresolvable (no_source),
   extension ownership unknown.
2. MCP BP tools never passed extension_name to RDBGClient.set_breakpoints,
   so the BP registered against the main-config namespace.

Live context (DEV_TAV_01_mss-dev1c02, extension SodruEDExhangeRulesAcc30):
frames of extension modules carry
`moduleID: {type: ExtensionModule, extensionName, version}`.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import uuid_index
from uuid_index import UUIDIndex

import mcp_debug_server as srv

COMMON_MODULE_PROP = "d5963243-262e-4398-b4d7-fb16d06484f6"
MAIN_UUID = "aaaa1111-aaaa-1111-aaaa-111111111111"
EXT_UUID = "bbbb2222-bbbb-2222-bbbb-222222222222"
EXT2_UUID = "cccc3333-cccc-3333-cccc-333333333333"


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """EDT workspace: main project + two extension projects (repo layout)."""
    ws = tmp_path / "DEV_WS"
    main = ws / "Конфигурация" / "src" / "CommonModules" / "ГлавныйМодуль"
    main.mkdir(parents=True)
    (main / "Module.bsl").write_text("// main\n", encoding="utf-8")
    (main / "ГлавныйМодуль.mdo").write_text(
        f'<mdclass:CommonModule xmlns:mdclass="..." uuid="{MAIN_UUID}">'
        "<name>ГлавныйМодуль</name></mdclass:CommonModule>",
        encoding="utf-8",
    )

    ext = ws / "Конфигурация.МоёРасширение" / "src"
    ext_cfg = ext / "Configuration"
    ext_cfg.mkdir(parents=True)
    (ext_cfg / "Configuration.mdo").write_text(
        '<mdclass:ConfigurationExtension xmlns:mdclass="..." '
        'uuid="dddd4444-dddd-4444-dddd-444444444444">'
        "<name>МоёРасширение</name><synonym><key>ru</key></synonym>"
        "</mdclass:ConfigurationExtension>",
        encoding="utf-8",
    )
    ext_mod = ext / "CommonModules" / "МодульРасширения"
    ext_mod.mkdir(parents=True)
    (ext_mod / "Module.bsl").write_text("// ext\n", encoding="utf-8")
    (ext_mod / "МодульРасширения.mdo").write_text(
        f'<mdclass:CommonModule xmlns:mdclass="..." uuid="{EXT_UUID}">'
        "<name>МодульРасширения</name></mdclass:CommonModule>",
        encoding="utf-8",
    )

    # Second extension WITHOUT Configuration.mdo — name falls back to dir suffix.
    ext2_mod = ws / "Конфигурация.Второе" / "src" / "CommonModules" / "ВтороеМодуль"
    ext2_mod.mkdir(parents=True)
    (ext2_mod / "Module.bsl").write_text("// ext2\n", encoding="utf-8")
    (ext2_mod / "ВтороеМодуль.mdo").write_text(
        f'<mdclass:CommonModule xmlns:mdclass="..." uuid="{EXT2_UUID}">'
        "<name>ВтороеМодуль</name></mdclass:CommonModule>",
        encoding="utf-8",
    )
    return ws


@pytest.fixture
def idx(workspace: Path, tmp_path: Path) -> UUIDIndex:
    return UUIDIndex(
        config_src=workspace / "Конфигурация" / "src",
        cache_path=tmp_path / "cache" / "idx.json",
    )


# ---------------------------------------------------------------------------
# uuid_index multi-root
# ---------------------------------------------------------------------------

class TestExtensionDiscovery:
    def test_extension_roots_discovered(self, idx: UUIDIndex):
        names = [n for n, _ in idx.extension_roots]
        assert "МоёРасширение" in names       # из Configuration.mdo <name>
        assert "Второе" in names              # фолбэк на суффикс каталога

    def test_extension_module_resolves(self, idx: UUIDIndex, workspace: Path):
        p = idx.resolve(EXT_UUID, COMMON_MODULE_PROP)
        assert p is not None and p.exists()
        assert "Конфигурация.МоёРасширение" in str(p)

    def test_extension_for(self, idx: UUIDIndex):
        assert idx.extension_for(EXT_UUID) == "МоёРасширение"
        assert idx.extension_for(MAIN_UUID) == ""
        assert idx.extension_for("nope-0000") == ""

    def test_get_source_info_carries_extension(self, idx: UUIDIndex):
        info = idx.get_source_info(EXT_UUID, COMMON_MODULE_PROP)
        assert info is not None
        assert info["extension"] == "МоёРасширение"
        assert info["exists"] is True
        main_info = idx.get_source_info(MAIN_UUID, COMMON_MODULE_PROP)
        assert main_info["extension"] == ""

    def test_main_wins_uuid_collision(self, workspace: Path, tmp_path: Path):
        """Adopted-in-extension object shares the base UUID — main must win."""
        clone = (workspace / "Конфигурация.МоёРасширение" / "src" /
                 "CommonModules" / "ГлавныйМодуль")
        clone.mkdir(parents=True)
        (clone / "Module.bsl").write_text("// adopted\n", encoding="utf-8")
        (clone / "ГлавныйМодуль.mdo").write_text(
            f'<mdclass:CommonModule xmlns:mdclass="..." uuid="{MAIN_UUID}">'
            "<name>ГлавныйМодуль</name></mdclass:CommonModule>",
            encoding="utf-8",
        )
        idx = UUIDIndex(
            config_src=workspace / "Конфигурация" / "src",
            cache_path=tmp_path / "cache" / "idx2.json",
        )
        assert idx.extension_for(MAIN_UUID) == ""
        p = idx.resolve(MAIN_UUID, COMMON_MODULE_PROP)
        assert "Конфигурация.МоёРасширение" not in str(p)

    def test_no_extensions_no_change(self, tmp_path: Path):
        """Workspace without extension projects behaves exactly pre-W5."""
        lone = tmp_path / "Solo" / "Конфигурация" / "src"
        lone.mkdir(parents=True)
        idx = UUIDIndex(config_src=lone, cache_path=tmp_path / "c.json")
        assert idx.extension_roots == []

    def test_cache_invalidated_by_new_extension(self, idx: UUIDIndex, workspace: Path, tmp_path: Path):
        idx.resolve(EXT_UUID, COMMON_MODULE_PROP)  # build + persist cache
        fp_before = idx._src_fingerprint()
        third = workspace / "Конфигурация.Третье" / "src" / "CommonModules" / "Т"
        third.mkdir(parents=True)
        (third / "Т.mdo").write_text(
            '<mdclass:CommonModule xmlns:mdclass="..." '
            'uuid="eeee5555-eeee-5555-eeee-555555555555"><name>Т</name>'
            "</mdclass:CommonModule>",
            encoding="utf-8",
        )
        idx2 = UUIDIndex(
            config_src=workspace / "Конфигурация" / "src",
            cache_path=idx.cache_path,
        )
        fp_after = idx2._src_fingerprint()
        assert fp_before != fp_after                      # roots в fingerprint
        assert idx2._load_cache(fp_after) is None         # старый кеш отвергнут

    def test_pre_w5_cache_rejected(self, idx: UUIDIndex):
        """A real pre-W5 cache FILE (fingerprint without 'roots') is rejected."""
        import json

        legacy_fp = {"max_mtime": 1.0, "count": 1, "total_size": 10}
        idx.cache_path.parent.mkdir(parents=True, exist_ok=True)
        idx.cache_path.write_text(
            json.dumps({"src_fingerprint": legacy_fp,
                        "entries": {"dead-uuid": {"mdo": "x", "name": "x",
                                                  "kind": "commonmodule",
                                                  "child_kind": None}}}),
            encoding="utf-8",
        )
        current_fp = idx._src_fingerprint()
        assert "roots" in current_fp
        # strict != between stored legacy fp and current fp → cache refused
        assert idx._load_cache(current_fp) is None
        # and the index rebuilt from disk does NOT contain the poisoned entry
        assert idx.lookup("dead-uuid") is None


class TestWorkspaceAlias:
    def test_workspace_candidate_rejects_traversal(self):
        assert uuid_index._workspace_candidate("..") is None
        assert uuid_index._workspace_candidate("a/b") is None
        assert uuid_index._workspace_candidate("a\\b") is None
        assert uuid_index._workspace_candidate("") is None
        # review 260812: Path(base) / "C:" discards base on Windows — colon
        # (and NUL, and embedded "..") must be rejected outright.
        assert uuid_index._workspace_candidate("C:") is None
        assert uuid_index._workspace_candidate("a\x00b") is None
        assert uuid_index._workspace_candidate("x..y") is None

    def test_unknown_alias_falls_back_to_default(self):
        idx = uuid_index.get_index_for_alias("no-such-workspace-alias-xyz")
        assert idx is uuid_index.get_default_index()

    def test_alias_autodiscovery_positive(self, workspace: Path, monkeypatch):
        """The headline W5 path: alias → <repo>/<alias>/Конфигурация/src."""
        monkeypatch.setattr(uuid_index, "_WORKSPACE_PARENT", workspace.parent)
        monkeypatch.setattr(uuid_index, "_indexes_by_alias", {})
        idx = uuid_index.get_index_for_alias(workspace.name)
        assert idx is not uuid_index.get_default_index()
        assert idx.config_src == workspace / "Конфигурация" / "src"
        assert idx.extension_for(EXT_UUID) == "МоёРасширение"

    def test_alias_autodiscovery_extension_only_workspace(self, tmp_path: Path, monkeypatch):
        """Workspace with ONLY extension projects (no main src) is accepted."""
        ws = tmp_path / "EXT_ONLY_WS"
        mod = ws / "Конфигурация.Соло" / "src" / "CommonModules" / "М"
        mod.mkdir(parents=True)
        (mod / "М.mdo").write_text(
            '<mdclass:CommonModule xmlns:mdclass="..." '
            'uuid="ffff6666-ffff-6666-ffff-666666666666"><name>М</name>'
            "</mdclass:CommonModule>",
            encoding="utf-8",
        )
        monkeypatch.setattr(uuid_index, "_WORKSPACE_PARENT", tmp_path)
        monkeypatch.setattr(uuid_index, "_indexes_by_alias", {})
        idx = uuid_index.get_index_for_alias("EXT_ONLY_WS")
        assert idx is not uuid_index.get_default_index()
        assert idx.extension_for("ffff6666-ffff-6666-ffff-666666666666") == "Соло"


# ---------------------------------------------------------------------------
# mcp_debug_server: XML shape + auto-extension + version cache
# ---------------------------------------------------------------------------

class TestModuleIdXml:
    def test_main_config_shape_unchanged(self):
        xml = srv._module_id_xml("ConfigModule", "oid-1", "pid-1")
        assert xml == (
            "<debugBaseData:type>ConfigModule</debugBaseData:type>"
            "<debugBaseData:objectID>oid-1</debugBaseData:objectID>"
            "<debugBaseData:propertyID>pid-1</debugBaseData:propertyID>"
        )

    def test_extension_fields_trailing(self):
        xml = srv._module_id_xml(
            "ExtensionModule", "oid-1", "pid-1",
            extension_name="МоёРасширение", version="0d61ff9b",
        )
        assert xml.index("objectID") < xml.index("extensionName") < xml.index("version")
        assert "<debugBaseData:extensionName>МоёРасширение</debugBaseData:extensionName>" in xml
        assert "<debugBaseData:version>0d61ff9b</debugBaseData:version>" in xml

    def test_empty_optionals_omitted(self):
        xml = srv._module_id_xml("ConfigModule", "oid", "pid", url="", extension_name="", ext_id=0, version="")
        assert "extensionName" not in xml
        assert "extId" not in xml
        assert "version" not in xml
        assert "url" not in xml


class TestAutoExtension:
    def test_auto_extension_failsoft(self, monkeypatch):
        monkeypatch.setattr(
            srv.uuid_index, "extension_of",
            lambda oid, alias=None: (_ for _ in ()).throw(RuntimeError("boom")),
        )
        assert srv._auto_extension("any-oid", "alias") == ""

    def test_auto_extension_resolves(self, monkeypatch):
        monkeypatch.setattr(
            srv.uuid_index, "extension_of", lambda oid, alias=None: "МоёРасширение"
        )
        assert srv._auto_extension("oid", None) == "МоёРасширение"


class _FakePost:
    """Capture set_breakpoints wire body instead of talking to dbgs."""
    def __init__(self):
        self.bodies = []

    async def __call__(self, path, body):
        self.bodies.append((path, body))
        return None


@pytest.fixture
def client(monkeypatch):
    c = srv.RDBGClient(infobase_alias="TestAlias")
    fake = _FakePost()
    monkeypatch.setattr(c, "_post", fake)
    monkeypatch.setattr(srv, "_parse_response", lambda root: [])
    c._fake_post = fake
    return c


class TestSetBreakpointsExtensionPlumbing:
    def test_auto_fill_extension_name(self, client, monkeypatch):
        monkeypatch.setattr(srv, "_auto_extension", lambda oid, alias=None: "МоёРасширение")
        asyncio.run(client.set_breakpoints(
            module_type="ConfigModule", object_id="oid-ext",
            property_id=COMMON_MODULE_PROP, lines=[10],
        ))
        _, body = client._fake_post.bodies[-1]
        assert "<debugBaseData:extensionName>МоёРасширение</debugBaseData:extensionName>" in body
        # ConfigModule → ExtensionModule for extension-owned modules
        assert "<debugBaseData:type>ExtensionModule</debugBaseData:type>" in body
        entry = client._set_breakpoints_cache[-1]
        assert entry["extension_name"] == "МоёРасширение"
        assert entry["module_type"] == "ExtensionModule"

    def test_main_config_untouched(self, client, monkeypatch):
        monkeypatch.setattr(srv, "_auto_extension", lambda oid, alias=None: "")
        asyncio.run(client.set_breakpoints(
            module_type="ConfigModule", object_id="oid-main",
            property_id=COMMON_MODULE_PROP, lines=[5],
        ))
        _, body = client._fake_post.bodies[-1]
        assert "extensionName" not in body
        assert "<debugBaseData:type>ConfigModule</debugBaseData:type>" in body

    def test_version_stamped_from_cache(self, client, monkeypatch):
        monkeypatch.setattr(srv, "_auto_extension", lambda oid, alias=None: "МоёРасширение")
        client._extension_versions["МоёРасширение"] = "0d61ff9b65dc"
        asyncio.run(client.set_breakpoints(
            module_type="ConfigModule", object_id="oid-ext",
            property_id=COMMON_MODULE_PROP, lines=[10],
        ))
        _, body = client._fake_post.bodies[-1]
        assert "<debugBaseData:version>0d61ff9b65dc</debugBaseData:version>" in body

    def test_explicit_extension_name_wins(self, client, monkeypatch):
        monkeypatch.setattr(
            srv, "_auto_extension",
            lambda oid, alias=None: pytest.fail("auto-resolve must not run"),
        )
        asyncio.run(client.set_breakpoints(
            module_type="ConfigModule", object_id="oid",
            property_id=COMMON_MODULE_PROP, lines=[1],
            extension_name="Явное",
        ))
        _, body = client._fake_post.bodies[-1]
        assert "<debugBaseData:extensionName>Явное</debugBaseData:extensionName>" in body

    def test_empty_string_forces_main_config(self, client, monkeypatch):
        """review 260812 opt-out: extension_name="" suppresses auto-resolve
        (escape hatch for a UUID misattributed to an extension)."""
        monkeypatch.setattr(
            srv, "_auto_extension",
            lambda oid, alias=None: pytest.fail("auto-resolve must not run on explicit ''"),
        )
        asyncio.run(client.set_breakpoints(
            module_type="ConfigModule", object_id="oid",
            property_id=COMMON_MODULE_PROP, lines=[1],
            extension_name="",
        ))
        _, body = client._fake_post.bodies[-1]
        assert "extensionName" not in body
        assert "<debugBaseData:type>ConfigModule</debugBaseData:type>" in body

    def test_calibrate_keep_nearest_normalizes_extension(self, client, monkeypatch):
        """review 260812 blocker: the calibrate keep-nearest fallback appends
        a cache entry directly (bypassing set_breakpoints) — it must apply the
        same ConfigModule→ExtensionModule conversion and version stamp, or the
        kept BP goes out in the documented-dead shape."""
        monkeypatch.setattr(srv, "_auto_extension", lambda oid, alias=None: "МоёРасширение")
        client._attached = True   # tool guards on this before touching calibrations
        client._extension_versions["МоёРасширение"] = "0d61ff9b65dc"
        client._calibrations = {
            "oid-ext": {
                "requested_line": 100,
                "lines": [98, 99, 100, 101],
                "property_id": COMMON_MODULE_PROP,
                "module_type": "CommonModule",
                "xml_module_type": "ConfigModule",   # pre-conversion, as captured
            }
        }
        # coverage tracker: line 100 actually fired → nearest = 100
        client._coverage_tracked = {
            ("oid-ext", COMMON_MODULE_PROP, 100): {"hits": 1},
        }
        # cache holds no fan for this module → fallback branch builds the entry
        client._set_breakpoints_cache = []
        monkeypatch.setattr(srv, "_persist_active_session", lambda c: None)
        monkeypatch.setattr(srv, "_get_client", lambda: client)

        async def _noop_reapply():
            return None

        monkeypatch.setattr(client, "_reapply_bp_workspace", _noop_reapply)
        asyncio.run(srv.debug_calibrate_result(
            object_id="oid-ext", clear=True, keep_bp_on_nearest=True
        ))
        entries = [e for e in client._set_breakpoints_cache if e["object_id"] == "oid-ext"]
        assert entries, "keep-nearest entry must be appended"
        entry = entries[-1]
        assert entry["module_type"] == "ExtensionModule"
        assert entry["extension_name"] == "МоёРасширение"
        assert entry["version"] == "0d61ff9b65dc"


class TestVersionHarvest:
    STACK = [
        {
            "moduleID": {
                "type": "ExtensionModule",
                "extensionName": "МоёРасширение",
                "objectID": "oid-ext",
                "propertyID": COMMON_MODULE_PROP,
                "version": "0d61ff9b65dc",
            },
            "lineNo": "27429",
        },
        {
            "moduleID": {
                "objectID": "oid-main",
                "propertyID": COMMON_MODULE_PROP,
                "version": "05a54dfdb984",  # main config: NO extensionName
            },
            "lineNo": "210",
        },
    ]

    def test_module_not_split_when_version_learned_midflight(self, client, monkeypatch):
        """Round-3 regression: `version` is part of the aggregation key, so a BP
        set BEFORE the extension version was learned and one set AFTER used to
        split the SAME module into two moduleBPInfo groups — the version-less
        one carrying the shape that does not fire."""
        monkeypatch.setattr(srv, "_auto_extension", lambda oid, alias=None: "МоёРасширение")

        async def scenario():
            await client.set_breakpoints(
                module_type="ConfigModule", object_id="oid-ext",
                property_id=COMMON_MODULE_PROP, lines=[10],
            )
            client._harvest_extension_versions([{
                "moduleID": {"type": "ExtensionModule",
                             "extensionName": "МоёРасширение",
                             "objectID": "oid-ext",
                             "propertyID": COMMON_MODULE_PROP,
                             "version": "v1"},
            }])
            await client.set_breakpoints(
                module_type="ConfigModule", object_id="oid-ext",
                property_id=COMMON_MODULE_PROP, lines=[20],
            )

        asyncio.run(scenario())
        _, body = client._fake_post.bodies[-1]
        assert body.count("<debugBreakpoints:moduleBPInfo>") == 1, "module must stay one group"
        assert body.count("<debugBreakpoints:line>") == 2, "both lines in that group"
        assert body.count("<debugBaseData:version>") == 1
        entries = [e for e in client._set_breakpoints_cache if e["object_id"] == "oid-ext"]
        assert len(entries) == 1
        assert entries[0]["version"] == "v1"
        assert sorted(entries[0]["lines"]) == [10, 20]

    def test_restamp_only_touches_its_own_extension(self, client):
        """Up-stamping one extension must not rewrite another's entries."""
        client._set_breakpoints_cache = [
            {"module_type": "ExtensionModule", "object_id": "a", "property_id": COMMON_MODULE_PROP,
             "lines": [1], "ext_id": 0, "url": "", "extension_name": "A", "version": "", "condition": ""},
            {"module_type": "ExtensionModule", "object_id": "b", "property_id": COMMON_MODULE_PROP,
             "lines": [2], "ext_id": 0, "url": "", "extension_name": "B", "version": "old", "condition": ""},
            {"module_type": "ConfigModule", "object_id": "m", "property_id": COMMON_MODULE_PROP,
             "lines": [3], "ext_id": 0, "url": "", "extension_name": "", "version": "", "condition": ""},
        ]
        assert client._restamp_extension_version("A", "vA") is True
        assert client._restamp_extension_version("A", "vA") is False  # idempotent
        versions = {e["extension_name"]: e["version"] for e in client._set_breakpoints_cache}
        assert versions == {"A": "vA", "B": "old", "": ""}

    def test_harvest_learns_extension_versions(self, client):
        learned = client._harvest_extension_versions(self.STACK)
        assert learned is True
        assert client._extension_versions == {"МоёРасширение": "0d61ff9b65dc"}
        # second pass: nothing new
        assert client._harvest_extension_versions(self.STACK) is False

    def test_harvest_tolerates_garbage(self, client):
        garbage = [{"moduleID": None}, {}, {"no": "mid"}, {"moduleID": "not-a-dict"}]
        assert client._harvest_extension_versions(garbage) is False
        assert client._harvest_extension_versions([]) is False
        assert client._harvest_extension_versions(None) is False

    def test_refresh_restamps_and_repushes(self, client, monkeypatch):
        client._set_breakpoints_cache.append({
            "module_type": "ExtensionModule", "object_id": "oid-ext",
            "property_id": COMMON_MODULE_PROP, "lines": [27429],
            "ext_id": 0, "url": "", "extension_name": "МоёРасширение",
            "version": "", "condition": "",
        })
        pushed = []

        async def fake_reapply():
            pushed.append(True)

        monkeypatch.setattr(client, "_reapply_bp_workspace", fake_reapply)
        monkeypatch.setattr(srv, "_persist_active_session", lambda c: None)
        client._extension_versions["МоёРасширение"] = "0d61ff9b65dc"
        asyncio.run(client._refresh_extension_bp_versions())
        assert pushed == [True]
        assert client._set_breakpoints_cache[0]["version"] == "0d61ff9b65dc"

    def test_refresh_noop_without_extension_entries(self, client, monkeypatch):
        client._set_breakpoints_cache.append({
            "module_type": "ConfigModule", "object_id": "oid-main",
            "property_id": COMMON_MODULE_PROP, "lines": [210],
            "ext_id": 0, "url": "", "extension_name": "", "version": "",
            "condition": "",
        })
        monkeypatch.setattr(
            client, "_reapply_bp_workspace",
            lambda: pytest.fail("must not re-push when nothing changed"),
        )
        monkeypatch.setattr(srv, "_persist_active_session", lambda c: None)
        client._extension_versions["МоёРасширение"] = "v1"
        asyncio.run(client._refresh_extension_bp_versions())
