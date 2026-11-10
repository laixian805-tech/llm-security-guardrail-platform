"""SkillSpector 适配器：Skill 静态扫描。

运行边界：静态扫描并关闭 LLM 分析；OSV 查询可能访问网络。
"""

from __future__ import annotations

from pathlib import Path

from domain import DetectorDescriptor, DetectorMode
from adapters.detectors.base import NormalizedFinding, RawOutput
from adapters.detectors.cli import CliDetectorAdapter
from adapters.detectors.normalize import normalize_report


class SkillSpectorAdapter(CliDetectorAdapter):
    @property
    def detector_id(self) -> str:
        return "skillspector"

    @property
    def binary(self) -> str:
        return "skillspector"

    @property
    def engine_version(self) -> str:
        return "2.12.0"

    @property
    def writes_report_file(self) -> bool:
        return True

    @property
    def signals_findings_via_exit_code(self) -> bool:
        # 实测：clean 退 0，有发现项退 1，报告照常写出。
        return True

    def descriptor(self) -> DetectorDescriptor:
        return DetectorDescriptor(
            detector_id=self.detector_id,
            version=self.engine_version,
            upstream_source="NVIDIA/SkillSpector",
            license_id="Apache-2.0",
            input_types=["skill_directory", "skill_md"],
            mode=DetectorMode.STATIC,
            capabilities=["sarif"],
            boundary="静态扫描；关闭 LLM 分析；OSV 查询可能访问网络",
        )

    def validate_target(self, target: Path) -> Path:
        return target

    def build_argv(self, target: Path, output_path: Path | None) -> list[str]:
        if output_path is None:
            raise ValueError("SkillSpector 需要报告输出文件")
        return [
            self.binary_path() or self.binary,
            "scan",
            str(target),
            "--no-llm",
            "--format",
            "sarif",
            "--output",
            str(output_path),
        ]

    def normalize(self, raw: RawOutput) -> list[NormalizedFinding]:
        return normalize_report(raw.report)
