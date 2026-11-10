"""检测器目录：detector_id 到适配器的映射。

增删扫描器只改这里的注册表，不改 Asset/Finding 服务。
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from adapters.detectors import (
    AigMcpScanAdapter,
    AigSkillScanAdapter,
    DetectorAdapter,
    McpScannerAdapter,
    SkillSpectorAdapter,
    SnykAgentScanAdapter,
)

ADAPTER_TYPES = {
    "skillspector": SkillSpectorAdapter,
    "snyk-agent-scan": SnykAgentScanAdapter,
    "mcp-scanner": McpScannerAdapter,
    "aig-skill-scan": AigSkillScanAdapter,
    "aig-mcp-scan": AigMcpScanAdapter,
}


class DetectorCatalog:
    """按需构造适配器实例；未注册的 detector_id 一律拒绝。"""

    def __init__(self, *, data_root: Path, timeout_seconds: int = 300,
                 max_output_bytes: int = 8 * 1024 * 1024,
                 probe_status: Callable[[str, str], str] | None = None) -> None:
        self._data_root = data_root
        self._timeout_seconds = timeout_seconds
        self._max_output_bytes = max_output_bytes
        self._probe_status = probe_status
        self._cache: dict[str, DetectorAdapter] = {}

    def ids(self) -> list[str]:
        return sorted(ADAPTER_TYPES)

    def get(self, detector_id: str) -> DetectorAdapter:
        adapter_type = ADAPTER_TYPES.get(detector_id)
        if adapter_type is None:
            raise KeyError(detector_id)
        cached = self._cache.get(detector_id)
        if cached is None:
            cached = adapter_type(
                data_root=self._data_root,
                timeout_seconds=self._timeout_seconds,
                max_output_bytes=self._max_output_bytes,
                probe_status=self._probe_status,
            )
            self._cache[detector_id] = cached
        return cached

    def descriptors(self) -> list:
        return [self.get(detector_id).descriptor() for detector_id in self.ids()]

    def health(self) -> dict[str, dict]:
        return {
            detector_id: {
                "installed": report.installed,
                "runnable": report.runnable,
                "reason": report.reason,
                "version": report.version,
            }
            for detector_id in self.ids()
            for report in (self.get(detector_id).health_check(),)
        }
