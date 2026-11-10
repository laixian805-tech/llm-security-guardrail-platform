"""检测器适配器集合。"""

from adapters.detectors.aig import AigMcpScanAdapter, AigSkillScanAdapter
from adapters.detectors.base import (
    DetectorAdapter,
    HealthReport,
    NormalizedFinding,
    RawOutput,
    ScanRequest,
)
from adapters.detectors.cli import CliDetectorAdapter
from adapters.detectors.errors import DetectorError, ErrorKind
from adapters.detectors.mcp_scanner import McpScannerAdapter
from adapters.detectors.skillspector import SkillSpectorAdapter
from adapters.detectors.snyk_agent_scan import SnykAgentScanAdapter

__all__ = [
    "AigMcpScanAdapter",
    "AigSkillScanAdapter",
    "CliDetectorAdapter",
    "DetectorAdapter",
    "DetectorError",
    "ErrorKind",
    "HealthReport",
    "McpScannerAdapter",
    "NormalizedFinding",
    "RawReport",
    "ScanRequest",
    "SkillSpectorAdapter",
    "SnykAgentScanAdapter",
]

# RawReport 是 RawOutput 的别名，供按 DATA_MODEL.md 术语引用的代码使用。
RawReport = RawOutput
