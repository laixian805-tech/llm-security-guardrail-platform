"""Snyk Agent Scan 适配器。

运行边界：仅允许扫描包含 SKILL.md 的目录或 SKILL.md 文件；需要 SNYK_TOKEN；
不会扫描可启动 MCP 命令的配置。
"""

from __future__ import annotations

import os
from pathlib import Path

from domain import DetectorDescriptor, DetectorMode
from adapters.detectors.base import NormalizedFinding, RawOutput
from adapters.detectors.cli import CliDetectorAdapter
from adapters.detectors.errors import DetectorError, ErrorKind
from adapters.detectors.normalize import normalize_report


class SnykAgentScanAdapter(CliDetectorAdapter):
    @property
    def detector_id(self) -> str:
        return "snyk-agent-scan"

    @property
    def binary(self) -> str:
        return "snyk-agent-scan"

    @property
    def engine_version(self) -> str:
        return "0.6.11"

    def descriptor(self) -> DetectorDescriptor:
        return DetectorDescriptor(
            detector_id=self.detector_id,
            version=self.engine_version,
            upstream_source="snyk/agent-scan",
            license_id="Apache-2.0",
            input_types=["skill_directory", "skill_md"],
            mode=DetectorMode.STATIC,
            capabilities=["json"],
            boundary="仅允许扫描 Skill；需 SNYK_TOKEN；CLI 输出格式仍可能变化",
        )

    def gate_reason(self) -> str:
        if not os.environ.get("SNYK_TOKEN"):
            return "运行 Snyk Agent Scan 前请设置 SNYK_TOKEN。"
        return ""

    def validate_target(self, target: Path) -> Path:
        is_skill_md = target.is_file() and target.name.lower() == "skill.md"
        is_skill_dir = target.is_dir() and (target / "SKILL.md").is_file()
        if not (is_skill_md or is_skill_dir):
            raise DetectorError(
                ErrorKind.INVALID_TARGET,
                "Snyk Agent Scan 仅允许扫描包含 SKILL.md 的目录或 SKILL.md 文件。",
            )
        return target

    def build_argv(self, target: Path, output_path: Path | None) -> list[str]:
        return [self.binary_path() or self.binary, str(target), "--json"]

    def normalize(self, raw: RawOutput) -> list[NormalizedFinding]:
        return normalize_report(raw.report)
