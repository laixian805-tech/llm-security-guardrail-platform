from __future__ import annotations

from pathlib import Path

from app.agent_security.asset_identity import (
    classify_carrier,
    derive_ids,
    derive_release_id,
    normalized_content_hash,
)
from app.agent_security.models import AssetCarrier, AssetKind, AssetState
from app.agent_security.scanner import Registry, scan_path
from app.agent_security.store import AgentSecStore


def test_carrier_classification_distinguishes_cache_installed_builtin_and_project() -> None:
    assert classify_carrier(
        "/root/.codex/.tmp/plugins/plugins/market/skills/demo/SKILL.md"
    ) == AssetCarrier.MARKETPLACE_CACHE
    assert classify_carrier("/root/.codex/skills/demo/SKILL.md") == AssetCarrier.USER_INSTALLED
    assert classify_carrier(
        "/root/.codex/skills/.system/review/SKILL.md"
    ) == AssetCarrier.PRODUCT_BUILTIN
    assert classify_carrier("/workspace/repo/.claude/skills/demo/SKILL.md") == AssetCarrier.PROJECT_LOCAL
    assert classify_carrier("/workspace/repo/env/docs/SKILL.md") == AssetCarrier.UNKNOWN


def test_logical_and_instance_ids_have_distinct_identity_inputs() -> None:
    first = derive_ids(product="codex", kind=AssetKind.SKILL, name="Demo",
                       host="host-a", carrier=AssetCarrier.USER_INSTALLED,
                       path="/root/.codex/skills/demo")
    other_copy = derive_ids(product="codex", kind=AssetKind.SKILL, name="demo",
                            host="host-b", carrier=AssetCarrier.MARKETPLACE_CACHE,
                            path="/root/.codex/.tmp/plugins/plugins/demo")
    assert first[0] == other_copy[0]
    assert first[1] != other_copy[1]


def test_release_identity_separates_versions_publishers_and_sources() -> None:
    logical = "logical-demo"
    release_a = derive_release_id(logical_id=logical, version="1.0.0",
                                  content_hash="a" * 64, source_uri="registry://official")
    release_b = derive_release_id(logical_id=logical, version="1.1.0",
                                  content_hash="a" * 64, source_uri="registry://official")
    release_c = derive_release_id(logical_id=logical, version="1.0.0",
                                  content_hash="b" * 64, source_uri="registry://unknown")
    assert len({release_a, release_b, release_c}) == 3


def test_normalized_content_hash_ignores_text_newline_style(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    (first / "SKILL.md").write_bytes(b"# Demo\r\nline\r\n")
    (second / "SKILL.md").write_bytes(b"# Demo\nline\n")
    assert normalized_content_hash(first) == normalized_content_hash(second)


def test_cache_scan_is_inventory_only_and_collapses_identical_content(tmp_path: Path) -> None:
    store = AgentSecStore(tmp_path / "agentsec.db")
    registry = Registry(tmp_path / "registry.json")
    paths = []
    for plugin in ("first", "second"):
        target = tmp_path / ".codex/.tmp/plugins/plugins" / plugin / "skills/shared"
        target.mkdir(parents=True)
        (target / "SKILL.md").write_text("# Shared\n", encoding="utf-8")
        paths.append(target)
        report = scan_path(target, host="host-a", registry=registry)[0]
        assert report.carrier == AssetCarrier.MARKETPLACE_CACHE
        assert report.state == AssetState.CACHED
        assert report.inventory_only is True
        store.record_scan(report)

    summary = store.asset_summary(host="host-a")
    cache = summary["marketplace_cache"]
    assert cache["repositories"] == 1
    assert cache["plugins"] == 2
    assert cache["instances"] == 2
    assert cache["definitions"] == 1
    assert summary["counts"]["cached"]["skill"]["marketplace_cache"] == 1
    assert store.list_events(event_type="scan_finding") == []
    assert len(store.list_assets(host="host-a")) == 2
