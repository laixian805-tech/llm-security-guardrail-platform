"""ModelProviderProfile 契约。

同一个供应商可以有多个传输 profile：Codex 使用的 Responses profile 和
扫描器 CLI 使用的 Chat Completions profile 是不同配置，不能因为供应商
相同就合并 endpoint。契约只保存 `secret_configured` 布尔状态，不保存
密钥本身。
"""

from __future__ import annotations

from pydantic import Field, model_validator

from domain.asset import StrictModel
from domain.enums import ProbeStatus, ProviderRole, WireApi


class WireProfile(StrictModel):
    """一条具体的传输配置。"""

    wire_api: WireApi
    base_url: str = ""
    model: str = ""
    source: str = Field(min_length=1)
    configured: bool = False
    secret_configured: bool = False
    capabilities: list[str] = Field(default_factory=list)


class ModelProviderProfile(StrictModel):
    provider_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    role: ProviderRole
    selected: bool = False
    probe_status: ProbeStatus = ProbeStatus.UNKNOWN

    codex_profile: WireProfile | None = None
    scanner_profile: WireProfile | None = None

    @model_validator(mode="after")
    def _check_candidate_not_routed(self) -> ModelProviderProfile:
        # Candidate 在 Probe 和能力验收通过前不进入默认路由。
        if self.role is ProviderRole.CANDIDATE and self.selected:
            if self.probe_status is not ProbeStatus.PASSED:
                raise ValueError("candidate provider 未通过 Probe 前不能被选中")
        return self
