"""控制台认证、授权与审计。

控制台用户和设备身份是两套凭证：会话令牌代表控制台用户并带角色权限，
设备令牌只证明一台端点有资格上报。authenticate() 只认会话令牌，设备令牌
走 resolve_device()，两者不互相顶替。

密码用 PBKDF2-HMAC-SHA256 加盐哈希，令牌只存 SHA-256；明文都只在创建的
那一刻返回。
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

from domain import (
    ActorKind,
    AuditOutcome,
    ConsoleRole,
    ConsoleUser,
    DeviceIdentity,
    DeviceStatus,
    Permission,
)
from storage.repositories import (
    AuditRepository,
    ConsoleAuthRepository,
    DeviceIdentityRepository,
    RetentionRepository,
    Storage,
    console_user_from_row,
    device_identity_from_row,
)

DEFAULT_SESSION_TTL_SECONDS = 12 * 60 * 60


class AuthError(Exception):
    def __init__(self, kind: str, detail: str) -> None:
        super().__init__(detail)
        self.kind = kind  # unauthenticated | forbidden
        self.detail = detail


class AuthService:
    def __init__(self, *, storage: Storage,
                 session_ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS) -> None:
        self._auth = ConsoleAuthRepository(storage)
        self._audit = AuditRepository(storage)
        self._devices = DeviceIdentityRepository(storage)
        self._retention = RetentionRepository(storage)
        self._storage = storage
        self._session_ttl = session_ttl_seconds

    # ---------- 引导 ----------

    def bootstrap_admin(self, *, password: str | None = None) -> tuple[str, str] | None:
        """确保至少有一个管理员。返回 (username, 明文密码) 或 None。

        没有用户时才创建。密码由调用方从环境变量提供，或这里生成一次性随机
        密码——不使用任何默认口令。
        """
        if self._auth.count_users():
            return None
        username = "admin"
        plain = password or secrets.token_urlsafe(24)
        self._auth.create_user(username=username, password=plain, role=ConsoleRole.ADMIN)
        return username, plain

    # ---------- 会话 ----------

    def login(self, *, username: str, password: str) -> dict:
        row = self._auth.find_user(username)
        # 用户不存在也算校验失败，不区分"无此用户"和"密码错误"。
        if row is None or not self._auth.verify_password(row, password):
            raise AuthError("unauthenticated", "用户名或密码不正确。")
        if row["disabled_at"]:
            raise AuthError("forbidden", "该账号已被停用。")
        session_id, token = self._auth.create_session(
            user_id=row["user_id"], ttl_seconds=self._session_ttl
        )
        return {"token": token, "session_id": session_id, "username": row["username"],
                "role": row["role"], "expires_in_seconds": self._session_ttl}

    def logout(self, *, session_id: str) -> None:
        self._auth.revoke_session(session_id)

    def authenticate(self, token: str) -> tuple[ConsoleUser, dict]:
        """用会话令牌换控制台用户。令牌无效、过期、被吊销或用户被停用都拒绝。"""
        if not token:
            raise AuthError("unauthenticated", "缺少访问令牌。")
        row = self._auth.resolve_session(token)
        if row is None:
            raise AuthError("unauthenticated", "访问令牌无效。")
        if row["disabled_at"]:
            raise AuthError("forbidden", "该账号已被停用。")
        if not console_session_valid(row):
            raise AuthError("unauthenticated", "会话已过期，请重新登录。")
        return console_user_from_row(row), row

    def resolve_device(self, token: str) -> DeviceIdentity:
        """设备令牌只换设备身份，不换控制台用户权限。"""
        if not token:
            raise AuthError("unauthenticated", "缺少设备令牌。")
        row = self._devices.resolve(token)
        if row is None:
            raise AuthError("unauthenticated", "设备令牌无效。")
        device = device_identity_from_row(row)
        if not device.can_report():
            raise AuthError("forbidden", "该设备已被停用或吊销。")
        self._devices.touch(device_id=device.device_id)
        return device

    def require(self, user: ConsoleUser, permission: Permission) -> None:
        if not user.can(permission):
            raise AuthError("forbidden", f"当前角色（{user.role.value}）没有 {permission.value} 权限。")

    # ---------- 用户管理 ----------

    def create_user(self, *, actor: ConsoleUser, username: str, password: str,
                    role: ConsoleRole) -> str:
        self.require(actor, Permission.MANAGE_USERS)
        if self._auth.find_user(username) is not None:
            raise AuthError("forbidden", f"用户名 {username} 已存在。")
        return self._auth.create_user(username=username, password=password, role=role)

    def list_users(self, *, actor: ConsoleUser) -> list[dict]:
        self.require(actor, Permission.MANAGE_USERS)
        return self._auth.list_users()

    def set_role(self, *, actor: ConsoleUser, user_id: str, role: ConsoleRole) -> None:
        self.require(actor, Permission.MANAGE_USERS)
        if user_id == actor.user_id:
            raise AuthError("forbidden", "不能修改自己的角色。")
        self._auth.set_role(user_id=user_id, role=role)

    def set_disabled(self, *, actor: ConsoleUser, user_id: str, disabled: bool) -> None:
        self.require(actor, Permission.MANAGE_USERS)
        if user_id == actor.user_id:
            raise AuthError("forbidden", "不能停用自己的账号。")
        self._auth.set_disabled(user_id=user_id, disabled=disabled)

    def change_password(self, *, user_id: str, old_password: str, new_password: str) -> None:
        row = self._auth.get_user(user_id)
        if row is None or not self._auth.verify_password(row, old_password):
            raise AuthError("forbidden", "原密码不正确。")
        if len(new_password) < 12:
            raise AuthError("forbidden", "新密码至少 12 位。")
        self._auth.set_password(user_id=user_id, password=new_password)

    # ---------- 设备 ----------

    def enroll_device(self, *, actor: ConsoleUser, label: str) -> dict:
        self.require(actor, Permission.MANAGE_USERS)
        device_id, token = self._devices.enroll(label=label)
        return {"device_id": device_id, "token": token}

    def list_devices(self, *, actor: ConsoleUser) -> list[dict]:
        self.require(actor, Permission.MANAGE_USERS)
        return self._devices.list()

    def set_device_status(self, *, actor: ConsoleUser, device_id: str,
                          status: DeviceStatus) -> None:
        self.require(actor, Permission.MANAGE_USERS)
        self._devices.set_status(device_id=device_id, status=status)

    # ---------- 审计 ----------

    def audit(self, *, request_id: str, actor_kind: ActorKind, actor_id: str, action: str,
              resource: str = "", outcome: AuditOutcome, detail: dict | None = None) -> None:
        self._audit.record(
            request_id=request_id, actor_kind=actor_kind, actor_id=actor_id, action=action,
            resource=resource, outcome=outcome, detail=detail,
        )

    def audit_events(self, *, actor: ConsoleUser, limit: int = 100,
                     actor_kind: str | None = None, action: str | None = None,
                     since: str | None = None) -> list[dict]:
        self.require(actor, Permission.READ_AUDIT)
        return self._audit.list(limit=limit, actor_kind=actor_kind, action=action, since=since)

    # ---------- 保留 ----------

    def retention_rules(self) -> list[dict]:
        return self._retention.rules()

    def set_retention_rule(self, *, actor: ConsoleUser, data_kind, retention_days: int,
                           enabled: bool) -> None:
        self.require(actor, Permission.MANAGE_RETENTION)
        self._retention.set_rule(data_kind=data_kind, retention_days=retention_days,
                                 enabled=enabled)

    def run_retention(self, *, actor: ConsoleUser, now: datetime | None = None) -> dict:
        self.require(actor, Permission.MANAGE_RETENTION)
        return self._retention.prune(now=now or datetime.now(timezone.utc))

    def purge_expired_sessions(self, *, now: datetime | None = None) -> int:
        return self._auth.purge_expired_sessions(now=now or datetime.now(timezone.utc))


def console_session_valid(row: dict) -> bool:
    """会话行是否仍然有效。 revoked_at 为空且未过期。"""
    if row.get("revoked_at"):
        return False
    expires_at = row.get("expires_at")
    if not expires_at:
        return False
    return datetime.fromisoformat(expires_at) > datetime.now(timezone.utc)
