"""控制台身份、审计与保留策略契约。

控制台用户和设备身份是两套东西：设备令牌只代表一台端点有资格上报，不等
于控制台用户的权限。审计记录 actor_kind 来保持这个区分，不允许把设备动
作记成某个用户的操作。

本包只放纯数据契约，不做 I/O、不碰密钥明文。
"""

from __future__ import annotations

from datetime import datetime

from pydantic import Field, model_validator

from domain.asset import StrictModel
from domain.enums import (
    ActorKind,
    AuditOutcome,
    ConsoleRole,
    DeviceStatus,
    Permission,
    RetentionKind,
)

# 角色 → 权限。viewer 只读；operator 可执行扫描和探测；admin 额外管用户和
# 保留策略。设备身份不在这张表里，它走单独的令牌。
ROLE_PERMISSIONS: dict[ConsoleRole, frozenset[Permission]] = {
    ConsoleRole.VIEWER: frozenset({Permission.READ}),
    ConsoleRole.OPERATOR: frozenset({
        Permission.READ, Permission.SCAN, Permission.PROBE, Permission.IMPORT_REPORT,
    }),
    ConsoleRole.ADMIN: frozenset({
        Permission.READ, Permission.SCAN, Permission.PROBE, Permission.IMPORT_REPORT,
        Permission.MANAGE_USERS, Permission.MANAGE_RETENTION, Permission.READ_AUDIT,
    }),
}


def permissions_for(role: ConsoleRole) -> frozenset[Permission]:
    return ROLE_PERMISSIONS[role]


class ConsoleUser(StrictModel):
    user_id: str = Field(min_length=1)
    username: str = Field(min_length=1)
    role: ConsoleRole
    created_at: datetime
    disabled_at: datetime | None = None

    @property
    def permissions(self) -> frozenset[Permission]:
        return permissions_for(self.role)

    def can(self, permission: Permission) -> bool:
        return self.disabled_at is None and permission in self.permissions


class ConsoleSession(StrictModel):
    session_id: str = Field(min_length=1)
    user_id: str = Field(min_length=1)
    created_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None

    def is_valid(self, *, now: datetime) -> bool:
        return self.revoked_at is None and self.expires_at > now


class DeviceIdentity(StrictModel):
    """端点设备身份。只有上报资格，没有控制台用户权限。"""

    device_id: str = Field(min_length=1)
    label: str = Field(min_length=1)
    status: DeviceStatus = DeviceStatus.ACTIVE
    enrolled_at: datetime
    last_seen_at: datetime | None = None

    def can_report(self) -> bool:
        return self.status is DeviceStatus.ACTIVE


class AuditEvent(StrictModel):
    audit_id: str = Field(min_length=1)
    occurred_at: datetime
    request_id: str = Field(min_length=1)
    actor_kind: ActorKind
    actor_id: str = Field(min_length=1)
    action: str = Field(min_length=1)
    resource: str = ""
    outcome: AuditOutcome
    detail: dict = Field(default_factory=dict)

    @model_validator(mode="after")
    def _check_actor_not_anonymous_on_success(self) -> AuditEvent:
        # 未认证来源不可能"成功"，否则审计会把无主动作记成合法操作。
        if self.actor_kind is ActorKind.ANONYMOUS and self.outcome is AuditOutcome.SUCCESS:
            raise ValueError("未认证来源不能记录为成功")
        return self


class RetentionRule(StrictModel):
    data_kind: RetentionKind
    retention_days: int = Field(ge=1)
    enabled: bool = True
    updated_at: datetime

    def cutoff(self, *, now: datetime) -> datetime:
        from datetime import timedelta

        return now - timedelta(days=self.retention_days)
