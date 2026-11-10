"""CLI 检测器适配器基类：统一的解析、执行、报错流程。

具体适配器只需声明能力、校验目标形态、构造 argv 和实现 normalize。
"""

from __future__ import annotations

from abc import abstractmethod
import hashlib
import json
import tempfile
from pathlib import Path
from typing import Callable

from adapters.detectors.base import (
    DetectorAdapter,
    HealthReport,
    RawOutput,
    ScanRequest,
)
from adapters.detectors.environment import (
    demotion_user,
    minimal_environment,
    prepare_workdir,
    preexec_for,
    resolve_binary,
)
from adapters.detectors.errors import DetectorError, ErrorKind
from adapters.detectors.subprocess import redact, run_bounded, secret_values


class CliDetectorAdapter(DetectorAdapter):
    """以子进程方式运行的检测器。"""

    def __init__(self, *, data_root: Path, timeout_seconds: int = 300,
                 max_output_bytes: int = 8 * 1024 * 1024,
                 probe_status: Callable[[str, str], str] | None = None) -> None:
        self._data_root = data_root
        self._timeout_seconds = timeout_seconds
        self._max_output_bytes = max_output_bytes
        # 需要 LLM 的扫描器用它查 Provider Probe 状态；candidate 未通过 Probe 不路由。
        self._probe_status = probe_status

    @property
    @abstractmethod
    def detector_id(self) -> str: ...

    @property
    @abstractmethod
    def binary(self) -> str: ...

    @property
    def engine_version(self) -> str:
        return "unknown"

    def binary_path(self) -> str | None:
        return resolve_binary(self.detector_id, self.binary)

    def health_check(self) -> HealthReport:
        path = self.binary_path()
        if not path:
            return HealthReport(installed=False, runnable=False, reason="未找到可执行文件")
        reason = self.gate_reason()
        if reason:
            return HealthReport(installed=True, runnable=False, reason=reason, version=self.engine_version)
        return HealthReport(installed=True, runnable=True, version=self.engine_version)

    def gate_reason(self) -> str:
        """返回不可运行的原因；空字符串表示可运行。"""
        return ""

    def scan(self, request: ScanRequest) -> RawOutput:
        target = self.validate_target(request.target)
        binary = self.binary_path()
        if not binary:
            raise DetectorError(ErrorKind.NOT_INSTALLED, f"{self.detector_id} 未安装或未配置")
        gate = self.gate_reason()
        if gate:
            raise DetectorError(ErrorKind.MISSING_CREDENTIAL, gate)

        demote_to = demotion_user()
        workdir = prepare_workdir(self._data_root, self.detector_id, demote_to)
        env = minimal_environment(self.detector_id, workdir=workdir, extra=self.secret_env)
        secrets = secret_values(self.secret_env)

        output_path: Path | None = None
        try:
            if self.writes_report_file:
                handle = tempfile.NamedTemporaryFile(
                    prefix=f"{self.detector_id}-", suffix=".json", dir=self._data_root, delete=False
                )
                output_path = Path(handle.name)
                handle.close()
                output_path.unlink(missing_ok=True)

            argv = self.build_argv(target, output_path)
            result = run_bounded(
                argv,
                env=env,
                cwd=workdir,
                timeout_seconds=request.timeout_seconds,
                max_output_bytes=request.max_output_bytes,
                preexec=preexec_for(demote_to),
            )

            if result.returncode != 0 and not self.signals_findings_via_exit_code:
                detail = (result.stderr.decode("utf-8", "replace") or
                          result.stdout.decode("utf-8", "replace") or "扫描器未提供错误详情").strip()[-2000:]
                raise DetectorError(
                    ErrorKind.NONZERO_EXIT,
                    f"{self.detector_id} 退出码 {result.returncode}：{redact(detail, secrets)}",
                )

            if output_path is not None:
                try:
                    payload = output_path.read_bytes()
                finally:
                    output_path.unlink(missing_ok=True)
            else:
                payload = result.stdout
        finally:
            # 任何失败路径都不留下含扫描内容的临时报告。
            if output_path is not None:
                output_path.unlink(missing_ok=True)

        if not payload.strip():
            if result.returncode != 0:
                raise DetectorError(
                    ErrorKind.NONZERO_EXIT,
                    f"{self.detector_id} 退出码 {result.returncode} 且未产生报告。",
                )
            raise DetectorError(ErrorKind.EMPTY_REPORT, f"{self.detector_id} 没有返回报告内容")

        try:
            report = json.loads(payload.decode("utf-8", "replace"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            tail = redact(result.stderr.decode("utf-8", "replace")[-1200:], secrets)
            raise DetectorError(ErrorKind.INVALID_JSON, f"{self.detector_id} 未返回可解析的 JSON：{tail}") from exc

        return RawOutput(
            report=report,
            media_type="application/json",
            sha256=hashlib.sha256(payload).hexdigest(),
            byte_length=len(payload),
            stderr_tail=redact(result.stderr.decode("utf-8", "replace")[-500:], secrets),
        )
