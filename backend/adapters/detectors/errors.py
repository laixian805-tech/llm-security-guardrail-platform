"""检测器错误分类。

错误类型决定 DetectorRun 的状态：超时和输出超限有独立状态，不能与
FAILED 混在一起，更不能呈现为 clean。
"""

from __future__ import annotations

from enum import StrEnum

from domain.enums import RunStatus


class ErrorKind(StrEnum):
    NOT_INSTALLED = "not_installed"
    INVALID_TARGET = "invalid_target"
    MISSING_CREDENTIAL = "missing_credential"
    UNSUPPORTED_MODE = "unsupported_mode"
    TIMEOUT = "timeout"
    OUTPUT_LIMIT = "output_limit"
    NONZERO_EXIT = "nonzero_exit"
    INVALID_JSON = "invalid_json"
    EMPTY_REPORT = "empty_report"


KIND_TO_RUN_STATUS: dict[ErrorKind, RunStatus] = {
    ErrorKind.TIMEOUT: RunStatus.TIMED_OUT,
    ErrorKind.OUTPUT_LIMIT: RunStatus.OUTPUT_LIMIT_EXCEEDED,
}


class DetectorError(Exception):
    """检测器执行或归一化失败。

    detail 已脱敏：密钥值在进入异常消息前被替换。
    """

    def __init__(self, kind: ErrorKind, detail: str) -> None:
        super().__init__(f"{kind}: {detail}")
        self.kind = kind
        self.detail = detail

    @property
    def run_status(self) -> RunStatus:
        return KIND_TO_RUN_STATUS.get(self.kind, RunStatus.FAILED)
