"""DetectorRun、RawReport 与检测器描述契约。

DetectorRun 记录一次检测器执行及其原始结果。运行失败必须与 clean
区分：只有 SUCCEEDED 且 finding_count 为 0 才算无发现项。
"""

from __future__ import annotations

from datetime import datetime

from pydantic import Field, model_validator

from domain.asset import StrictModel
from domain.enums import DetectorMode, RunStatus, WireApi


class RawReportRef(StrictModel):
    """原始报告的存储引用；内容不在契约内联。"""

    raw_report_id: str = Field(min_length=1)
    uri: str = Field(min_length=1)
    media_type: str = Field(min_length=1)
    sha256: str = Field(min_length=1)
    byte_length: int = Field(ge=0)


class DetectorRun(StrictModel):
    detector_run_id: str = Field(min_length=1)
    detector_id: str = Field(min_length=1)
    detector_version: str = Field(min_length=1)

    asset_id: str | None = None
    instance_id: str | None = None
    target_ref: str = Field(min_length=1)
    mode: DetectorMode

    status: RunStatus
    started_at: datetime
    finished_at: datetime | None = None
    timeout_seconds: int = Field(gt=0)
    error: str | None = None

    raw_report: RawReportRef | None = None
    # 归一化器版本，用于重放和重新归一化。
    normalizer_version: str = Field(min_length=1)
    finding_count: int = Field(default=0, ge=0)

    # 调用了模型服务时记录 profile 与协议；不记录 prompt 正文或密钥。
    provider_profile_id: str | None = None
    model_id: str | None = None
    wire_api: WireApi | None = None
    latency_ms: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def _check_terminal_state(self) -> DetectorRun:
        if self.status is RunStatus.SUCCEEDED and self.finished_at is None:
            raise ValueError("SUCCEEDED 的 DetectorRun 必须记录 finished_at")
        if self.status is not RunStatus.SUCCEEDED and self.status not in (
            RunStatus.QUEUED,
            RunStatus.RUNNING,
        ):
            if self.error is None:
                raise ValueError("非成功状态的 DetectorRun 必须记录 error")
        return self

    @property
    def is_clean(self) -> bool:
        """只有执行成功且没有发现项才是 clean。

        超时、失败和输出超限都不是 clean，界面与 API 不得把它们显示为
        无发现项。
        """
        return self.status is RunStatus.SUCCEEDED and self.finding_count == 0


class DetectorDescriptor(StrictModel):
    """检测器的静态能力声明，由 Adapter 提供。"""

    detector_id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    upstream_source: str = Field(min_length=1)
    license_id: str = Field(min_length=1)
    input_types: list[str] = Field(min_length=1)
    mode: DetectorMode
    network_required: bool = False
    llm_required: bool = False
    # 能力标签，例如 sarif、json、static_tool_list。
    capabilities: list[str] = Field(default_factory=list)
    # 运行边界说明，直接展示给用户。
    boundary: str = ""
