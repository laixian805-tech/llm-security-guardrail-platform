"""审批针对一次调用及其参数摘要；批准不能被另一调用或另一设备复用。"""
from datetime import datetime
from typing import Literal
from pydantic import Field
from domain.asset import StrictModel


class ApprovalRequest(StrictModel):
    approval_id: str = Field(min_length=1)
    device_id: str = Field(min_length=1)
    host_id: str = Field(min_length=1)
    product: Literal['codex','claude-code']
    product_version: str = Field(min_length=1)
    session_id: str = Field(min_length=1)
    tool_call_id: str = Field(min_length=1)
    tool_name: str = Field(min_length=1)
    params_sha256: str = Field(pattern='^[0-9a-f]{64}$')
    state: Literal['pending','approved','denied','expired']
    requested_at: datetime
    expires_at: datetime
    resolved_at: datetime | None = None
    resolved_by: str | None = None
