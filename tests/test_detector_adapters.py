"""DetectorAdapter 契约测试。

IMPLEMENTATION_PLAN.md P0 验收要求：对每个 DetectorAdapter 执行一致的
契约测试——成功、无发现项、部分结果、超时、错误退出、无效 JSON、输出超限。
这里用可编排的假 CLI 复现全部七种行为；行为由目标文件名驱动，因为适配器
只把必要变量注入子进程环境，测试用的开关必须走 argv 才符合真实约束。
"""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from adapters.detectors import (
    DetectorError,
    ErrorKind,
    NormalizedFinding,
    RawOutput,
    ScanRequest,
)
from adapters.detectors.cli import CliDetectorAdapter
from adapters.detectors.normalize import (
    make_fingerprint,
    map_severity,
    normalize_report,
    sarif_findings,
)
from domain import DetectorDescriptor, DetectorMode, Severity

FAKE_SCRIPT = '''#!/usr/bin/env python3
import json, os, sys, time

mode = os.path.basename(sys.argv[1]).split(".")[0]

if mode == "slow":
    time.sleep(30)
elif mode == "spam":
    sys.stdout.write("x" * 20000000)
elif mode == "badjson":
    sys.stdout.write("this is not json")
elif mode == "empty":
    pass
elif mode == "fail":
    sys.stderr.write("boom: token=" + os.environ.get("LLM_API_KEY", ""))
    sys.exit(3)
elif mode == "exit1":
    sys.stdout.write(json.dumps({"findings": [
        {"rule_id": "R9", "title": "t", "severity": "high"},
    ]}))
    sys.exit(1)
elif mode == "exit1bare":
    sys.exit(1)
elif mode == "partial":
    sys.stdout.write(json.dumps({"findings": [
        {"rule_id": "R1", "title": "t"},
        "not-a-dict",
        {"rule_id": "R2", "severity": "critical"},
    ]}))
elif mode == "clean":
    sys.stdout.write(json.dumps({"findings": []}))
else:
    sys.stdout.write(json.dumps({"findings": [
        {"rule_id": "R1", "title": "t", "severity": "high",
         "message": "m", "file": "a.py", "line": 3},
    ]}))
'''


class FakeAdapter(CliDetectorAdapter):
    """按目标文件名编排行为的假检测器。"""

    def __init__(self, *, data_root: Path, secret_env: dict[str, str] | None = None, **kwargs) -> None:
        super().__init__(data_root=data_root, **kwargs)
        self._secrets = secret_env or {}

    @property
    def detector_id(self) -> str:
        return "fake"

    @property
    def binary(self) -> str:
        return "fake"

    @property
    def engine_version(self) -> str:
        return "9.9.9"

    @property
    def secret_env(self) -> dict[str, str]:
        return self._secrets

    def descriptor(self) -> DetectorDescriptor:
        return DetectorDescriptor(
            detector_id=self.detector_id,
            version=self.engine_version,
            upstream_source="test/fake",
            license_id="MIT",
            input_types=["any"],
            mode=DetectorMode.STATIC,
        )

    def validate_target(self, target: Path) -> Path:
        return target

    def build_argv(self, target: Path, output_path: Path | None) -> list[str]:
        return [self.binary_path() or self.binary, str(target)]

    def normalize(self, raw: RawOutput) -> list[NormalizedFinding]:
        return normalize_report(raw.report)


@pytest.fixture
def fake_cli(tmp_path: Path) -> Path:
    script = tmp_path / "fake"
    script.write_text(FAKE_SCRIPT, encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return script


@pytest.fixture
def adapter(tmp_path: Path, fake_cli: Path, monkeypatch) -> FakeAdapter:
    monkeypatch.setenv("FUSION_BIN_FAKE", str(fake_cli))
    return FakeAdapter(data_root=tmp_path / "data")


def make_target(tmp_path: Path, mode: str) -> Path:
    path = tmp_path / f"{mode}.txt"
    path.write_text("sample", encoding="utf-8")
    return path


def scan(adapter: FakeAdapter, target: Path, **kwargs) -> RawOutput:
    return adapter.scan(ScanRequest(target=target, target_ref=target.name, **kwargs))


class TestContractScenarios:
    def test_success_returns_normalized_findings(self, adapter, tmp_path):
        raw = scan(adapter, make_target(tmp_path, "ok"))
        findings = adapter.normalize(raw)
        assert len(findings) == 1
        assert findings[0].rule_id == "R1"
        assert findings[0].severity is Severity.HIGH

    def test_clean_report_yields_no_findings(self, adapter, tmp_path):
        raw = scan(adapter, make_target(tmp_path, "clean"))
        assert adapter.normalize(raw) == []

    def test_partial_results_keep_parseable_rows(self, adapter, tmp_path):
        raw = scan(adapter, make_target(tmp_path, "partial"))
        findings = adapter.normalize(raw)
        assert [f.rule_id for f in findings] == ["R1", "R2"]
        # 缺字段时 severity 不得猜测，保持 unknown。
        assert findings[0].severity is Severity.UNKNOWN
        assert findings[1].severity is Severity.CRITICAL

    def test_timeout_is_reported_as_timeout(self, adapter, tmp_path):
        with pytest.raises(DetectorError) as excinfo:
            scan(adapter, make_target(tmp_path, "slow"), timeout_seconds=1)
        assert excinfo.value.kind is ErrorKind.TIMEOUT
        assert excinfo.value.run_status.value == "timed_out"

    def test_nonzero_exit_is_reported_as_failure(self, adapter, tmp_path):
        with pytest.raises(DetectorError) as excinfo:
            scan(adapter, make_target(tmp_path, "fail"))
        assert excinfo.value.kind is ErrorKind.NONZERO_EXIT
        assert excinfo.value.run_status.value == "failed"

    def test_error_detail_redacts_secrets(self, tmp_path, fake_cli, monkeypatch):
        monkeypatch.setenv("FUSION_BIN_FAKE", str(fake_cli))
        adapter = FakeAdapter(
            data_root=tmp_path / "data",
            secret_env={"LLM_API_KEY": "SUPERSECRETVALUE123"},
        )
        with pytest.raises(DetectorError) as excinfo:
            scan(adapter, make_target(tmp_path, "fail"))
        assert "SUPERSECRETVALUE123" not in excinfo.value.detail
        assert "[密钥已脱敏]" in excinfo.value.detail

    def test_invalid_json_is_reported(self, adapter, tmp_path):
        with pytest.raises(DetectorError) as excinfo:
            scan(adapter, make_target(tmp_path, "badjson"))
        assert excinfo.value.kind is ErrorKind.INVALID_JSON

    def test_empty_output_is_reported(self, adapter, tmp_path):
        with pytest.raises(DetectorError) as excinfo:
            scan(adapter, make_target(tmp_path, "empty"))
        assert excinfo.value.kind is ErrorKind.EMPTY_REPORT

    def test_output_limit_terminates_scanner(self, adapter, tmp_path):
        with pytest.raises(DetectorError) as excinfo:
            scan(adapter, make_target(tmp_path, "spam"),
                 max_output_bytes=64 * 1024, timeout_seconds=60)
        assert excinfo.value.kind is ErrorKind.OUTPUT_LIMIT
        assert excinfo.value.run_status.value == "output_limit_exceeded"

    def test_missing_binary_is_not_installed(self, tmp_path, monkeypatch):
        monkeypatch.setenv("FUSION_BIN_FAKE", str(tmp_path / "does-not-exist"))
        monkeypatch.setattr("shutil.which", lambda _name: None)
        adapter = FakeAdapter(data_root=tmp_path / "data")
        with pytest.raises(DetectorError) as excinfo:
            scan(adapter, make_target(tmp_path, "ok"))
        assert excinfo.value.kind is ErrorKind.NOT_INSTALLED

    def test_argv_carries_no_secret(self, tmp_path, fake_cli, monkeypatch):
        monkeypatch.setenv("FUSION_BIN_FAKE", str(fake_cli))
        seen: list[list[str]] = []
        adapter = FakeAdapter(
            data_root=tmp_path / "data",
            secret_env={"LLM_API_KEY": "SUPERSECRETVALUE123"},
        )
        original = adapter.build_argv

        def spy(target, output_path):
            argv = original(target, output_path)
            seen.append(argv)
            return argv

        adapter.build_argv = spy  # type: ignore[method-assign]
        scan(adapter, make_target(tmp_path, "ok"))
        assert seen, "适配器必须构造 argv"
        for argv in seen:
            assert all("SUPERSECRETVALUE123" not in part for part in argv)


class TestExitCodeSemantics:
    """非零退出码的含义按扫描器而定，必须逐个体检并写进适配器。"""

    def test_scanner_that_signals_findings_via_exit_code_is_not_a_failure(
        self, tmp_path, fake_cli, monkeypatch
    ):
        monkeypatch.setenv("FUSION_BIN_FAKE", str(fake_cli))

        class SignallingAdapter(FakeAdapter):
            @property
            def signals_findings_via_exit_code(self) -> bool:
                return True

        adapter = SignallingAdapter(data_root=tmp_path / "data")
        raw = scan(adapter, make_target(tmp_path, "exit1"))
        findings = adapter.normalize(raw)
        assert [f.rule_id for f in findings] == ["R9"]

    def test_same_exit_code_is_a_failure_without_the_declaration(self, adapter, tmp_path):
        with pytest.raises(DetectorError) as excinfo:
            scan(adapter, make_target(tmp_path, "exit1"))
        assert excinfo.value.kind is ErrorKind.NONZERO_EXIT

    def test_signalling_scanner_without_report_still_fails(self, tmp_path, fake_cli, monkeypatch):
        monkeypatch.setenv("FUSION_BIN_FAKE", str(fake_cli))

        class SignallingAdapter(FakeAdapter):
            @property
            def signals_findings_via_exit_code(self) -> bool:
                return True

        adapter = SignallingAdapter(data_root=tmp_path / "data")
        with pytest.raises(DetectorError) as excinfo:
            scan(adapter, make_target(tmp_path, "exit1bare"))
        assert excinfo.value.kind is ErrorKind.NONZERO_EXIT


class TestSeverityMapping:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("critical", Severity.CRITICAL),
            ("error", Severity.CRITICAL),
            ("HIGH", Severity.HIGH),
            ("warning", Severity.HIGH),
            ("medium", Severity.MEDIUM),
            ("low", Severity.LOW),
            ("info", Severity.INFO),
            ("", Severity.UNKNOWN),
            (None, Severity.UNKNOWN),
            ("banana", Severity.UNKNOWN),
        ],
    )
    def test_mapping(self, raw, expected):
        assert map_severity(raw) is expected


class TestSarifNormalization:
    def test_sarif_keeps_upstream_rule_and_location(self):
        report = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "skillspector", "rules": [
                        {"id": "SP-1", "shortDescription": {"text": "Prompt injection"},
                         "defaultConfiguration": {"level": "error"}},
                    ]}},
                    "results": [
                        {
                            "ruleId": "SP-1",
                            "level": "warning",
                            "message": {"text": "detected"},
                            "locations": [{"physicalLocation": {
                                "artifactLocation": {"uri": "SKILL.md"},
                                "region": {"startLine": 12},
                            }}],
                            "properties": {"security-severity": "8.5"},
                        }
                    ],
                }
            ],
        }
        findings = sarif_findings(report)
        assert len(findings) == 1
        finding = findings[0]
        assert finding.upstream_rule_id == "SP-1"
        assert finding.severity is Severity.HIGH
        assert finding.upstream_risk_score == 8.5
        assert finding.evidence_refs[0].uri == "SKILL.md:12"
        assert finding.fingerprint

    def test_non_sarif_input_returns_nothing(self):
        assert sarif_findings({"version": "1.0"}) == []
        assert sarif_findings(["not", "a", "dict"]) == []

    def test_dispatch_prefers_sarif(self):
        assert normalize_report({"version": "2.1.0", "runs": []}) == []
        assert normalize_report({"scan_path_responses": []}) == []
        assert normalize_report({"findings": [{"rule_id": "X", "title": "t"}]})[0].rule_id == "X"


class TestFingerprint:
    def test_stable_and_distinguishing(self):
        a = make_fingerprint("d", "r", "f.py", "msg")
        b = make_fingerprint("d", "r", "f.py", "msg")
        c = make_fingerprint("d", "r", "g.py", "msg")
        assert a == b
        assert a != c

    def test_normalizes_case_and_whitespace(self):
        assert make_fingerprint("d", "r", "F.py ", "msg") == make_fingerprint("d", "r", "f.py", "msg")


class TestRawOutputReference:
    def test_raw_output_carries_hash_not_content(self):
        raw = RawOutput(report={"findings": []}, media_type="application/json",
                        sha256="0" * 64, byte_length=12)
        assert raw.sha256 == "0" * 64
        assert raw.byte_length == 12
