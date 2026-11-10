"""真实引擎端到端测试。

用版本化夹具驱动 SkillSpector 与 Cisco MCP Scanner，验证适配器在真实
CLI 上的行为：有发现项、clean、以及各自的退出码语义。引擎未安装时跳过，
不因为缺依赖让契约测试失败。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from adapters.detectors import DetectorError, ScanRequest
from adapters.detectors.environment import resolve_binary
from detectors.registry import DetectorCatalog

FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(scope="module")
def catalog(tmp_path_factory) -> DetectorCatalog:
    return DetectorCatalog(data_root=tmp_path_factory.mktemp("engine-data"))


def requires(detector_id: str, binary: str):
    return pytest.mark.skipif(
        resolve_binary(detector_id, binary) is None,
        reason=f"{detector_id} 未安装",
    )


@pytest.mark.parametrize(
    "detector_id,binary",
    [("skillspector", "skillspector"), ("mcp-scanner", "mcp-scanner")],
)
def test_detector_reports_installed(catalog, detector_id, binary):
    report = catalog.get(detector_id).health_check()
    if resolve_binary(detector_id, binary) is None:
        pytest.skip(f"{detector_id} 未安装")
    assert report.installed is True
    assert report.runnable is True, report.reason


@requires("skillspector", "skillspector")
def test_skillspector_finds_prompt_injection(catalog, tmp_path):
    target = tmp_path / "demo-skill"
    target.mkdir()
    (target / "SKILL.md").write_text(
        (FIXTURES / "skills" / "demo-skill.SKILL.md").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    adapter = catalog.get("skillspector")
    raw = adapter.scan(ScanRequest(target=target, target_ref="demo-skill", timeout_seconds=180))
    findings = adapter.normalize(raw)
    assert findings, "演示夹具包含提示注入和凭据访问，应产生发现项"
    rule_ids = {f.rule_id for f in findings}
    assert "P1" in rule_ids, rule_ids
    assert "PE3" in rule_ids, rule_ids
    # 每条发现项都带位置证据。
    assert all(f.evidence_refs for f in findings)
    assert all(f.severity.value != "unknown" for f in findings)


@requires("skillspector", "skillspector")
def test_skillspector_clean_target_has_no_findings(catalog, tmp_path):
    target = tmp_path / "benign-skill"
    target.mkdir()
    (target / "SKILL.md").write_text(
        (FIXTURES / "skills" / "benign-skill.SKILL.md").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    adapter = catalog.get("skillspector")
    raw = adapter.scan(ScanRequest(target=target, target_ref="benign-skill", timeout_seconds=180))
    assert adapter.normalize(raw) == []


@requires("mcp-scanner", "mcp-scanner")
def test_mcp_scanner_flags_malicious_tool_list(catalog):
    adapter = catalog.get("mcp-scanner")
    target = FIXTURES / "mcp" / "tools-evil.json"
    raw = adapter.scan(ScanRequest(target=target, target_ref="tools-evil.json", timeout_seconds=180))
    findings = adapter.normalize(raw)
    assert findings, "恶意工具清单应产生发现项"
    assert findings[0].upstream_rule_id == "yara_analyzer"
    # Cisco 扫描器给 analyzer 等级；severity 来自上游映射而非猜测。
    assert findings[0].severity.value == "high"


@requires("mcp-scanner", "mcp-scanner")
def test_mcp_scanner_rejects_non_json_target(catalog, tmp_path):
    target = tmp_path / "notes.txt"
    target.write_text("not a tool list", encoding="utf-8")
    with pytest.raises(DetectorError) as excinfo:
        catalog.get("mcp-scanner").scan(ScanRequest(target=target, target_ref="notes.txt"))
    assert excinfo.value.kind.value == "invalid_target"


@requires("skillspector", "skillspector")
def test_snyk_adapter_rejects_non_skill_target(catalog, tmp_path):
    """Snyk 目标形态校验不依赖 SNYK_TOKEN，未装引擎也应拒绝错误形态。"""
    from adapters.detectors.snyk_agent_scan import SnykAgentScanAdapter

    target = tmp_path / "random.txt"
    target.write_text("x", encoding="utf-8")
    adapter = SnykAgentScanAdapter(data_root=tmp_path / "data")
    with pytest.raises(DetectorError) as excinfo:
        adapter.scan(ScanRequest(target=target, target_ref="random.txt"))
    assert excinfo.value.kind.value == "invalid_target"
