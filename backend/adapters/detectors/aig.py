"""A.I.G Skill/MCP 扫描适配器的共享逻辑。

运行边界：这两个扫描器会把目标内容发送给当前选定的模型服务，必须由用户
明确启动。密钥由 model_providers 在内存解析，只进入子进程环境。
"""

from __future__ import annotations

from pathlib import Path

from domain import DetectorDescriptor, DetectorMode
from adapters.detectors.base import NormalizedFinding, RawOutput
from adapters.detectors.cli import CliDetectorAdapter
from adapters.detectors.errors import DetectorError, ErrorKind
from adapters.detectors.normalize import normalize_report

AIG_SOURCE = "Tencent/AI-Infra-Guard"
AIG_LICENSE = "Apache-2.0 + NOTICE"
AIG_BOUNDARY = "调用配置的 LLM 服务，目标内容会发送给该服务"


class AigScannerAdapter(CliDetectorAdapter):
    @property
    def writes_report_file(self) -> bool:
        return True

    @property
    def secret_env(self) -> dict[str, str]:
        # 延迟导入避免控制面在无模型配置时无法加载适配器目录。
        from model_providers import scanner_provider_environment

        return scanner_provider_environment(probe_status=self._probe_status)

    def gate_reason(self) -> str:
        try:
            self.secret_env
        except ValueError as exc:
            return str(exc)
        return ""

    def build_argv(self, target: Path, output_path: Path | None) -> list[str]:
        if output_path is None:
            raise ValueError(f"{self.detector_id} 需要报告输出文件")
        return [
            self.binary_path() or self.binary,
            "--repo",
            str(target),
            "--language",
            "en",
            "-o",
            str(output_path),
        ]

    def normalize(self, raw: RawOutput) -> list[NormalizedFinding]:
        return normalize_report(raw.report)

    def _descriptor(self, *, detector_id: str, input_types: list[str], purpose_boundary: str) -> DetectorDescriptor:
        return DetectorDescriptor(
            detector_id=detector_id,
            version=self.engine_version,
            upstream_source=AIG_SOURCE,
            license_id=AIG_LICENSE,
            input_types=input_types,
            mode=DetectorMode.STATIC,
            llm_required=True,
            capabilities=["sarif"],
            boundary=purpose_boundary,
        )


class AigSkillScanAdapter(AigScannerAdapter):
    @property
    def detector_id(self) -> str:
        return "aig-skill-scan"

    @property
    def binary(self) -> str:
        return "aig-skill-scan"

    @property
    def engine_version(self) -> str:
        return "0.2.2"

    def descriptor(self) -> DetectorDescriptor:
        return self._descriptor(
            detector_id=self.detector_id,
            input_types=["skill_directory", "skill_md"],
            purpose_boundary=f"LLM 辅助 Skill 审计；{AIG_BOUNDARY}",
        )

    def validate_target(self, target: Path) -> Path:
        if target.is_file():
            if target.name.lower() != "skill.md":
                raise DetectorError(
                    ErrorKind.INVALID_TARGET,
                    "A.I.G Skill Scan 需要 Skill 目录或 SKILL.md 文件。",
                )
            return target.parent
        if not (target / "SKILL.md").is_file():
            raise DetectorError(
                ErrorKind.INVALID_TARGET,
                "A.I.G Skill Scan 需要包含 SKILL.md 的 Skill 目录。",
            )
        return target


class AigMcpScanAdapter(AigScannerAdapter):
    @property
    def detector_id(self) -> str:
        return "aig-mcp-scan"

    @property
    def binary(self) -> str:
        return "aig-mcp-scan"

    @property
    def engine_version(self) -> str:
        return "0.2.0"

    def descriptor(self) -> DetectorDescriptor:
        return self._descriptor(
            detector_id=self.detector_id,
            input_types=["source_directory"],
            purpose_boundary=f"LLM 辅助 MCP 源码审计；{AIG_BOUNDARY}",
        )

    def validate_target(self, target: Path) -> Path:
        if not target.is_dir():
            raise DetectorError(
                ErrorKind.INVALID_TARGET,
                "A.I.G MCP Scan 需要源码目录；在线 MCP URL 扫描未开放。",
            )
        return target
