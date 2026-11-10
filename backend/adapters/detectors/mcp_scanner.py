"""Cisco MCP Scanner 适配器：静态工具清单扫描。

运行边界：只运行静态工具清单模式，不连接远程服务，不启动 stdio MCP 进程。
"""

from __future__ import annotations

from pathlib import Path

from domain import DetectorDescriptor, DetectorMode
from adapters.detectors.base import NormalizedFinding, RawOutput
from adapters.detectors.cli import CliDetectorAdapter
from adapters.detectors.errors import DetectorError, ErrorKind
from adapters.detectors.normalize import normalize_report


class McpScannerAdapter(CliDetectorAdapter):
    @property
    def detector_id(self) -> str:
        return "mcp-scanner"

    @property
    def binary(self) -> str:
        return "mcp-scanner"

    @property
    def engine_version(self) -> str:
        return "4.8.7"

    def descriptor(self) -> DetectorDescriptor:
        return DetectorDescriptor(
            detector_id=self.detector_id,
            version=self.engine_version,
            upstream_source="cisco-ai-defense/mcp-scanner",
            license_id="Apache-2.0",
            input_types=["mcp_tools_json"],
            mode=DetectorMode.STATIC,
            capabilities=["json"],
            boundary="仅扫描静态工具清单 JSON；不连接或启动 MCP 服务",
        )

    def validate_target(self, target: Path) -> Path:
        if not target.is_file() or target.suffix.lower() != ".json":
            raise DetectorError(
                ErrorKind.INVALID_TARGET,
                "Cisco MCP Scanner 适配器只接受静态工具清单 JSON 文件。",
            )
        return target

    def build_argv(self, target: Path, output_path: Path | None) -> list[str]:
        return [
            self.binary_path() or self.binary,
            "--log-level",
            "error",
            "--analyzers",
            "yara",
            "--format",
            "raw",
            "static",
            "--tools",
            str(target),
        ]

    def normalize(self, raw: RawOutput) -> list[NormalizedFinding]:
        return normalize_report(raw.report)
