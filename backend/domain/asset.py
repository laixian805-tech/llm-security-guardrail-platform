"""Asset、AssetInstance、AssetRelease 契约。

逻辑身份、实例身份和内容版本必须分开：同一个 Skill 在 Claude Code 和
Codex 下共享 logical asset，但是不同 instance；instance 相同也不保证
当前内容与上次扫描一致。
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from domain.enums import (
    ActivationState,
    AssetType,
    InstallationState,
    RuntimeState,
)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=False)


class Asset(StrictModel):
    """逻辑治理对象。"""

    asset_id: str = Field(min_length=1)
    asset_type: AssetType
    canonical_name: str = Field(min_length=1)
    product: str | None = None
    publisher: str | None = None
    namespace: str | None = None
    # provenance 只记录来源和获取渠道，不代表安全结论。
    provenance: str | None = None
    created_at: datetime
    updated_at: datetime


class AssetInstance(StrictModel):
    """一个主机/产品/作用域中的具体安装或缓存副本。

    安装、启用、运行三种状态相互独立，不能相互推导。
    """

    instance_id: str = Field(min_length=1)
    asset_id: str = Field(min_length=1)
    host_id: str = Field(min_length=1)
    product_scope: str = Field(min_length=1)
    install_path: str | None = None
    installation_state: InstallationState = InstallationState.UNKNOWN
    activation_state: ActivationState = ActivationState.UNKNOWN
    runtime_state: RuntimeState = RuntimeState.UNKNOWN
    first_seen_at: datetime
    last_seen_at: datetime


class Publisher(StrictModel):
    """受信任的资产发布方公钥登记。"""

    publisher_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    public_key: str = Field(min_length=1)
    algorithm: str = "ed25519"
    status: str = "active"
    created_at: datetime
    revoked_at: datetime | None = None


class AssetRelease(StrictModel):
    """可验证内容版本。signature_verified 只能由服务端验签后写入。"""

    release_id: str = Field(min_length=1)
    asset_id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    content_hash: str = Field(min_length=1)
    source_uri: str | None = None
    publisher_id: str | None = None
    signature: str | None = None
    signature_verified: bool = False
    verified_at: datetime | None = None
    published_at: datetime | None = None
