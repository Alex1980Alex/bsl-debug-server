"""Unit tests for uuid_index — RDBG objectID UUID → BSL path resolution."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from uuid_index import UUIDIndex, MODULE_PROPERTY_FILES


COMMON_MODULE_PROP = "d5963243-262e-4398-b4d7-fb16d06484f6"
MANAGER_MODULE_PROP = "d1b64a2c-8078-4982-8190-8f81aefda192"
OBJECT_MODULE_PROP = "a637f77f-3840-441d-a1c3-699c8c5cb7e0"
FORM_MODULE_PROP = "32e087ab-1491-49b6-aba7-43571b41ac2b"
COMMAND_MODULE_PROP = "078a6af8-d22c-4248-9c33-7e90075a3d2c"


@pytest.fixture
def synthetic_src(tmp_path: Path) -> Path:
    """Mimic EDT export structure with 3 objects + nested forms/commands."""
    src = tmp_path / "src"
    cm_dir = src / "CommonModules" / "ОбщегоНазначения"
    cm_dir.mkdir(parents=True)
    (cm_dir / "Module.bsl").write_text("// common\n")
    (cm_dir / "ОбщегоНазначения.mdo").write_text(
        '<mdclass:CommonModule xmlns:mdclass="..." uuid="aaaa1111-aaaa-1111-aaaa-111111111111">'
        '<name>ОбщегоНазначения</name>'
        '</mdclass:CommonModule>',
        encoding="utf-8",
    )
    doc_dir = src / "Documents" / "ТестовыйДокумент"
    doc_dir.mkdir(parents=True)
    (doc_dir / "ObjectModule.bsl").write_text("// object\n")
    (doc_dir / "ManagerModule.bsl").write_text("// manager\n")
    (doc_dir / "Forms" / "ФормаДокумента").mkdir(parents=True)
    (doc_dir / "Forms" / "ФормаДокумента" / "Module.bsl").write_text("// form\n")
    (doc_dir / "Forms" / "ФормаСписка").mkdir(parents=True)
    (doc_dir / "Forms" / "ФормаСписка" / "Module.bsl").write_text("// list form\n")
    (doc_dir / "Commands" / "КомандаПечати").mkdir(parents=True)
    (doc_dir / "Commands" / "КомандаПечати" / "CommandModule.bsl").write_text("// cmd\n")
    (doc_dir / "ТестовыйДокумент.mdo").write_text(
        '<mdclass:Document xmlns:mdclass="..." uuid="bbbb2222-bbbb-2222-bbbb-222222222222">'
        '<name>ТестовыйДокумент</name>'
        '<forms uuid="cccc3333-cccc-3333-cccc-333333333333">'
        '<name>ФормаДокумента</name>'
        '</forms>'
        '<forms uuid="dddd4444-dddd-4444-dddd-444444444444">'
        '<name>ФормаСписка</name>'
        '</forms>'
        '<commands uuid="eeee5555-eeee-5555-eeee-555555555555">'
        '<name>КомандаПечати</name>'
        '</commands>'
        '</mdclass:Document>',
        encoding="utf-8",
    )
    return src


@pytest.fixture
def index(synthetic_src: Path, tmp_path: Path) -> UUIDIndex:
    return UUIDIndex(config_src=synthetic_src, cache_path=tmp_path / "cache.json")


class TestUUIDIndexBasic:
    def test_resolves_common_module(self, index, synthetic_src):
        path = index.resolve(
            "aaaa1111-aaaa-1111-aaaa-111111111111", COMMON_MODULE_PROP)
        assert path == synthetic_src / "CommonModules" / "ОбщегоНазначения" / "Module.bsl"
        assert path.exists()

    def test_resolves_document_object_module(self, index, synthetic_src):
        path = index.resolve(
            "bbbb2222-bbbb-2222-bbbb-222222222222", OBJECT_MODULE_PROP)
        assert path == synthetic_src / "Documents" / "ТестовыйДокумент" / "ObjectModule.bsl"

    def test_resolves_document_manager_module(self, index):
        path = index.resolve(
            "bbbb2222-bbbb-2222-bbbb-222222222222", MANAGER_MODULE_PROP)
        assert path.name == "ManagerModule.bsl"

    def test_resolves_form_module_by_form_uuid(self, index, synthetic_src):
        path = index.resolve(
            "cccc3333-cccc-3333-cccc-333333333333", FORM_MODULE_PROP)
        assert path == (
            synthetic_src / "Documents" / "ТестовыйДокумент"
            / "Forms" / "ФормаДокумента" / "Module.bsl"
        )
        assert path.exists()

    def test_resolves_second_form_distinctly(self, index):
        path = index.resolve(
            "dddd4444-dddd-4444-dddd-444444444444", FORM_MODULE_PROP)
        assert "ФормаСписка" in str(path)

    def test_resolves_command_module(self, index):
        path = index.resolve(
            "eeee5555-eeee-5555-eeee-555555555555", COMMAND_MODULE_PROP)
        assert path.name == "CommandModule.bsl"
        assert "КомандаПечати" in str(path)

    def test_unknown_uuid_returns_none(self, index):
        assert index.resolve("00000000-0000-0000-0000-000000000000", FORM_MODULE_PROP) is None

    def test_unknown_property_returns_none(self, index):
        assert index.resolve(
            "aaaa1111-aaaa-1111-aaaa-111111111111", "ffffffff-ffff-ffff-ffff-ffffffffffff",
        ) is None

    def test_case_insensitive_uuid(self, index):
        upper = "AAAA1111-AAAA-1111-AAAA-111111111111"
        path = index.resolve(upper, COMMON_MODULE_PROP)
        assert path is not None
        assert path.exists()


class TestUUIDIndexCache:
    def test_lookup_returns_metadata(self, index):
        rec = index.lookup("aaaa1111-aaaa-1111-aaaa-111111111111")
        assert rec is not None
        assert rec["name"] == "ОбщегоНазначения"
        assert rec["kind"].lower() == "commonmodule"
        assert rec["child_kind"] is None

    def test_lookup_form_metadata(self, index):
        rec = index.lookup("cccc3333-cccc-3333-cccc-333333333333")
        assert rec["name"] == "ФормаДокумента"
        assert rec["child_kind"] == "forms"

    def test_cache_persists_across_instances(self, synthetic_src, tmp_path):
        cache_file = tmp_path / "cache.json"
        idx1 = UUIDIndex(config_src=synthetic_src, cache_path=cache_file)
        idx1.resolve("aaaa1111-aaaa-1111-aaaa-111111111111", COMMON_MODULE_PROP)
        assert cache_file.exists()
        idx2 = UUIDIndex(config_src=synthetic_src, cache_path=cache_file)
        rec = idx2.lookup("aaaa1111-aaaa-1111-aaaa-111111111111")
        assert rec is not None

    def test_reset_clears_cache(self, index):
        index.resolve("aaaa1111-aaaa-1111-aaaa-111111111111", COMMON_MODULE_PROP)
        assert index._index is not None
        index.reset()
        assert index._index is None


class TestUUIDIndexEdgeCases:
    def test_empty_src(self, tmp_path):
        empty_src = tmp_path / "empty"
        empty_src.mkdir()
        idx = UUIDIndex(config_src=empty_src, cache_path=tmp_path / "c.json")
        assert idx.resolve("aaaa1111-aaaa-1111-aaaa-111111111111", FORM_MODULE_PROP) is None

    def test_nonexistent_src(self, tmp_path):
        idx = UUIDIndex(config_src=tmp_path / "nope", cache_path=tmp_path / "c.json")
        assert idx.resolve("aaaa1111-aaaa-1111-aaaa-111111111111", FORM_MODULE_PROP) is None

    def test_module_property_files_table_complete(self):
        assert len(MODULE_PROPERTY_FILES) == 6
        for prop_id, (filename, _) in MODULE_PROPERTY_FILES.items():
            assert filename.endswith(".bsl")
