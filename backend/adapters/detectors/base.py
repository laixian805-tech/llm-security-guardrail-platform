"""DetectorAdapter 统一接口。

检测器只产出检测观察：不写 Asset 生命周期、不创建 Incident、不直接执行
治理动作。适配器负责协议转换和子进程隔离，归一化结果交给领域服务持久化。
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from domain import (
    Confidence,
    DetectorDescriptor,
    EvidenceRef,
    Severity,
)


@dataclass(frozen=True)
class ScanRequest:
    """一次扫描请求。target 必须是已校验的绝对路径。"""

    target: Path
    target_ref: str
    timeout_seconds: int = 300
    max_output_bytes: int = 8 * 1024 * 1024
    options: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RawOutput:
    """一次检测器执行的原始结果。

    保留原始报告供重放和重新归一化；只存哈希和长度，不在契约内联正文。
    """

    report: Any
    media_type: str
    sha256: str
    byte_length: int
    stderr_tail: str = ""


@dataclass(frozen=True)
class NormalizedFinding:
    """归一化后的发现项，尚未持久化。

    detector_id / detector_version 由服务层按适配器描述补齐；适配器的
    normalize() 只负责把上游输出映射成标准字段。
    """

    rule_id: str
    title: str
    severity: Severity = Severity.UNKNOWN
    confidence: Confidence = Confidence.UNKNOWN
    message: str = ""
    upstream_rule_id: str | None = None
    upstream_risk_score: float | None = None
    evidence_refs: tuple[EvidenceRef, ...] = ()
    fingerprint: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)
    detector_id: str = ""
    detector_version: str = ""


@dataclass(frozen=True)
class HealthReport:
    installed: bool
    runnable: bool
    reason: str = ""
    version: str = ""


class DetectorAdapter(ABC):
    """所有检测器适配器必须实现的契约。"""

    @abstractmethod
    def descriptor(self) -> DetectorDescriptor:
        """静态能力声明，含运行边界说明。"""

    @abstractmethod
    def health_check(self) -> HealthReport:
        """检查安装与运行环境，不执行扫描。"""

    @abstractmethod
    def validate_target(self, target: Path) -> Path:
        """校验目标是否在本适配器支持的形态内，可返回调整后的目标。"""

    @abstractmethod
    def build_argv(self, target: Path, output_path: Path | None) -> list[str]:
        """构造子进程 argv。output_path 非空表示扫描器写文件。"""

    @abstractmethod
    def normalize(self, raw: RawOutput) -> list[NormalizedFinding]:
        """把原始输出转为标准发现项，保留上游规则 ID 和证据引用。"""

    @property
    def writes_report_file(self) -> bool:
        """扫描器是否把报告写入文件而非 stdout。"""
        return False

    @property
    def secret_env(self) -> dict[str, str]:
        """需要注入子进程的密钥环境变量；默认无。"""
        return {}

    @property
    def signals_findings_via_exit_code(self) -> bool:
        """扫描器是否用非零退出码表示"有发现项"。

        已实测：SkillSpector  clean 退 0、有发现项退 1；Cisco MCP Scanner
        两种情况都退 0。默认按退出码判定成败——未实测的扫描器保持严格，
        宁可报失败也不把未解析的报告当成 clean。
        """
        return False
