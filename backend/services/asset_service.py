"""资产台账服务：登记、查询与追踪视图。

三态（安装/启用/运行）不在库里存一份"声明值"，而是每次查询时按平台真正
持有的证据现算：

- installation_state ← 准入事务。只有安装器真的落盘并被复核过才记 installed；
  回滚到 first_install 记 absent；失败（磁盘内容与声明不符）记 unknown，
  因为不重新 verify 就说不清磁盘上是什么。
- runtime_state ← 执行记录。有 outcome=running 的执行记 running，只有已收尾
  的执行记 stopped，从未被任何执行引用记 unknown。
- activation_state 由准入事务的 product_loaded 派生：产品会话确认加载才 enabled，
  探测不可用记 unknown（未验证），产品否认或回滚记 disabled。
  准入带 product_id 时的加载结论记在准入记录自己的 product_loaded 上，且
  探测不可用时是 None（未验证）而不是 False，台账不把它挪成启用状态。
  客户端声明启用状态一律拒绝，否则就变成了"看起来已启用"。

台账对 executions/admissions 里的存量 asset_instance_id 不回溯校验：查得到
就呈现，查不到按未登记处理，不猜。
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from domain import Asset, AssetInstance, AssetRelease, Publisher
from domain.enums import (
    ActivationState,
    AdmissionState,
    AssetType,
    InstallationState,
    RuntimeState,
)
from services.ed25519 import parse_public_key, parse_signature, verify_ed25519
from services.ingestion_service import IngestError, reject_secrets
from storage.asset_repositories import (
    AssetRepository,
    asset_from_row,
    asset_instance_from_row,
    asset_release_from_row,
    new_asset_id,
    new_instance_id,
    new_publisher_id,
    new_release_id,
    publisher_from_row,
)
from storage.repositories import Storage

NOW = lambda: datetime.now(timezone.utc)

# 安装器真正落过盘的状态。与 GovernanceService.INSTALLED_STATES 保持一致：
# 只有这些状态能证明磁盘上有内容。
ON_DISK_STATES = frozenset({
    AdmissionState.COMMITTED.value,
    AdmissionState.VERIFIED.value,
    AdmissionState.RECONCILED.value,
})

ASSET_FIELDS = {"asset_type", "canonical_name", "product", "publisher", "namespace", "provenance"}
INSTANCE_FIELDS = {"asset_id", "host_id", "product_scope", "install_path"}
PUBLISHER_FIELDS = {"name", "public_key", "algorithm"}
RELEASE_FIELDS = {"asset_id", "version", "content_hash", "source_uri",
                  "publisher_id", "signature", "published_at"}

# 各分段的关联方式写进响应，界面和时间线都按原样展示：哪些是显式登记的、
# 哪些是字符串匹配，不能混同为采集器证明的因果。
TRACE_LINKS = {
    "release": "登记时由服务端使用 publishers 公钥对 content_hash 做 Ed25519 验签；未提供签名时记为未验证",
    "instance": "登记时声明的主机/产品作用域副本",
    "admission": "按 admissions.asset_instance_id 字符串匹配（P1 遗留自由文本，无外键）",
    "execution": "按 executions.asset_instance_id 字符串匹配（P1 遗留自由文本，无外键）",
    # findings.asset_id 一列存在，但没有任何写入方（record_success 的 INSERT 不含它，
    # 留存清理只置空 detector_run_id）。在这里提它等于虚报一条走不到的通道，而本字段
    # 的职责恰恰是如实披露关联强度。将来要接，先在 record_success 落列并定清
    # (detector_id, fingerprint) 跨资产去重时的归属，再把话加回来。
    "finding": "分析员显式关联（execution_findings），不是自动归因",
    "policy_decision": "按 subject_id 匹配资产/实例/发现项/执行/准入标识",
    "incident": "按 incident_evidence 关联到上述发现项或执行",
    "activation_state": "按最近一次带 product_id 的准入事务派生：只有产品会话真的确认加载才记 enabled；"
                        "探测不可用记 unknown（未验证），回滚或产品否认记 disabled",
}


def _text(value: Any, field: str, *, maximum: int = 200, required: bool = False) -> str | None:
    if value is None:
        if required:
            raise IngestError(f"{field}_required")
        return None
    if not isinstance(value, str):
        raise IngestError(f"invalid_{field}")
    text = value.strip()
    if not text:
        if required:
            raise IngestError(f"{field}_required")
        return None
    if len(text) > maximum:
        raise IngestError(f"{field}_too_long")
    return text


def _content_hash(value: Any) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(
        c not in "0123456789abcdef" for c in value
    ):
        raise IngestError("invalid_content_hash")
    return value


def derive_installation_state(admissions: list[dict[str, Any]]) -> str:
    """按准入事务推导安装状态；admissions 须按 updated_at 倒序。"""
    if not admissions:
        return InstallationState.UNKNOWN.value
    for row in admissions:
        if row["state"] in ON_DISK_STATES:
            return InstallationState.INSTALLED.value
        if row["state"] == AdmissionState.FAILED.value:
            # 磁盘内容与审批声明不符。不重新 verify 前不能断言已安装或缺失。
            return InstallationState.UNKNOWN.value
        if row["state"] == AdmissionState.ROLLED_BACK.value:
            if row["rollback_ref"] == "first_install":
                return InstallationState.ABSENT.value
            # 恢复的是提交前快照，落盘内容就是那个快照。
            return InstallationState.INSTALLED.value
    # 只剩 check/approved/staged：事务未完结，磁盘状态未知。
    return InstallationState.UNKNOWN.value


def derive_runtime_state(executions: list[dict[str, Any]]) -> str:
    if not executions:
        return RuntimeState.UNKNOWN.value
    if any(row["outcome"] == "running" for row in executions):
        return RuntimeState.RUNNING.value
    return RuntimeState.STOPPED.value


# product_loaded 在 SQLite 里是 INTEGER，读出来可能是 0/1/None；统一成三态布尔。
def _loaded_flag(value: Any) -> bool | None:
    return None if value is None else bool(value)


ACTIVATED_STATES = {AdmissionState.VERIFIED.value, AdmissionState.RECONCILED.value}


def derive_activation_state(admissions: list[dict[str, Any]]) -> str:
    """推导"产品会不会加载这个包"；admissions 须按 updated_at 倒序。

    这是平台唯一有产品侧证据的激活判据。三条纪律：

    1. **目录里有文件不算激活**：只有产品会话真的认识这个 skill
       （``product_loaded=True`` 且事务已 verify）才记 enabled。
    2. **探测不可用记 unknown，不记 enabled**：没有证据就说没有证据。
    3. **没有 product_id 也记 unknown**：包只进了平台托管存储，产品侧
       根本不存在这回事，不是"已启用"也不是"已禁用"。
    """
    targeted = [row for row in admissions if row.get("product_id")]
    if not targeted:
        return ActivationState.UNKNOWN.value
    latest = targeted[0]
    state, loaded = latest.get("state"), _loaded_flag(latest.get("product_loaded"))
    if state == AdmissionState.ROLLED_BACK.value:
        return ActivationState.DISABLED.value
    if state == AdmissionState.FAILED.value or loaded is False:
        return ActivationState.DISABLED.value
    if state in ACTIVATED_STATES and loaded is True:
        return ActivationState.ENABLED.value
    # verified 但产品探测没给出结论（无 CLI/超时/缺凭据），或事务尚未 verify。
    return ActivationState.UNKNOWN.value


class AssetService:
    def __init__(self, storage: Storage) -> None:
        self.storage = storage
        self.repo = AssetRepository(storage)

    # ---------- 登记 ----------

    def register_asset(self, body: dict[str, Any]) -> dict[str, Any]:
        reject_secrets(body)
        if set(body) - ASSET_FIELDS:
            raise IngestError("invalid_asset_input")
        asset_type = AssetType(str(body.get("asset_type") or ""))
        canonical_name = _text(body.get("canonical_name"), "canonical_name",
                               maximum=200, required=True)
        product = _text(body.get("product"), "product", maximum=60)
        existing = self.repo.find_asset_by_name(asset_type=asset_type.value,
                                                canonical_name=canonical_name,
                                                product=product)
        if existing:
            # 同名同类型同产品的逻辑资产只登记一次；重复登记返回原行，
            # 不分裂出第二个"同一个 Skill"。
            return {"asset": asset_from_row(existing).model_dump(mode="json"), "duplicate": True}
        now = NOW()
        model = Asset(asset_id=new_asset_id(), asset_type=asset_type,
                      canonical_name=canonical_name, product=product,
                      publisher=_text(body.get("publisher"), "publisher", maximum=120),
                      namespace=_text(body.get("namespace"), "namespace", maximum=120),
                      provenance=_text(body.get("provenance"), "provenance", maximum=200),
                      created_at=now, updated_at=now)
        return {"asset": self.repo.create_asset(model).model_dump(mode="json"),
                "duplicate": False}

    def register_instance(self, body: dict[str, Any]) -> dict[str, Any]:
        reject_secrets(body)
        if set(body) - INSTANCE_FIELDS:
            raise IngestError("invalid_asset_instance_input")
        asset_id = _text(body.get("asset_id"), "asset_id", maximum=64, required=True)
        host_id = _text(body.get("host_id"), "host_id", maximum=160, required=True)
        product_scope = _text(body.get("product_scope"), "product_scope",
                              maximum=120, required=True)
        install_path = _text(body.get("install_path"), "install_path", maximum=500)
        if not self.repo.get_asset(asset_id):
            raise IngestError("unknown_asset", 404)
        existing = self.repo.find_instance(asset_id=asset_id, host_id=host_id,
                                           product_scope=product_scope)
        if existing:
            if install_path:
                self.repo.fill_install_path(instance_id=existing["instance_id"],
                                            install_path=install_path)
            else:
                self.repo.touch_instance(existing["instance_id"])
            refreshed = self.repo.get_instance(existing["instance_id"])
            return {"instance": asset_instance_from_row(refreshed).model_dump(mode="json"),
                "duplicate": True}
        now = NOW()
        model = AssetInstance(instance_id=new_instance_id(), asset_id=asset_id,
                              host_id=host_id, product_scope=product_scope,
                              install_path=install_path, first_seen_at=now, last_seen_at=now)
        return {"instance": self.repo.create_instance(model).model_dump(mode="json"),
                "duplicate": False}

    def register_publisher(self, body: dict[str, Any]) -> dict[str, Any]:
        reject_secrets(body)
        if set(body) - PUBLISHER_FIELDS:
            raise IngestError("invalid_publisher_input")
        name = _text(body.get("name"), "name", maximum=120, required=True)
        algorithm = _text(body.get("algorithm"), "algorithm", maximum=32) or "ed25519"
        if algorithm != "ed25519":
            raise IngestError("unsupported_signature_algorithm")
        raw_key = _text(body.get("public_key"), "public_key", maximum=256, required=True)
        key_bytes = parse_public_key(raw_key)
        if key_bytes is None:
            raise IngestError("invalid_public_key")
        canonical_key = key_bytes.hex()
        existing = self.repo.find_publisher_by_name(name)
        if existing:
            if existing["public_key"] != canonical_key:
                raise IngestError("publisher_key_conflict", 409)
            return {"publisher": publisher_from_row(existing).model_dump(mode="json"),
                    "duplicate": True}
        model = Publisher(
            publisher_id=new_publisher_id(),
            name=name,
            public_key=canonical_key,
            algorithm="ed25519",
            status="active",
            created_at=NOW(),
        )
        return {"publisher": self.repo.create_publisher(model).model_dump(mode="json"),
                "duplicate": False}

    def list_publishers(self, *, limit: int = 100) -> dict[str, Any]:
        rows = self.repo.list_publishers(limit=limit)
        return {"items": [publisher_from_row(row).model_dump(mode="json") for row in rows]}

    def revoke_publisher(self, publisher_id: str) -> dict[str, Any]:
        if not self.repo.get_publisher(publisher_id):
            raise IngestError("unknown_publisher", 404)
        updated = self.repo.revoke_publisher(publisher_id)
        return {"publisher": publisher_from_row(updated).model_dump(mode="json")}

    def register_release(self, body: dict[str, Any]) -> dict[str, Any]:
        reject_secrets(body)
        # 绝不采信客户端自报的 signature_verified；必须由服务端用公钥验签。
        if "signature_verified" in body:
            raise IngestError("client_signature_verified_forbidden")
        if set(body) - RELEASE_FIELDS:
            raise IngestError("invalid_asset_release_input")
        asset_id = _text(body.get("asset_id"), "asset_id", maximum=64, required=True)
        version = _text(body.get("version"), "version", maximum=120, required=True)
        content_hash = _content_hash(body.get("content_hash"))
        publisher_id = _text(body.get("publisher_id"), "publisher_id", maximum=64)
        signature_raw = _text(body.get("signature"), "signature", maximum=256)
        if bool(publisher_id) != bool(signature_raw):
            raise IngestError("signature_requires_publisher_and_signature")
        published_at = body.get("published_at")
        published = None
        if published_at is not None:
            if not isinstance(published_at, str):
                raise IngestError("invalid_published_at")
            try:
                published = datetime.fromisoformat(published_at)
            except ValueError:
                raise IngestError("invalid_published_at") from None
        if not self.repo.get_asset(asset_id):
            raise IngestError("unknown_asset", 404)

        canonical_sig = None
        signature_verified = False
        verified_at = None
        if publisher_id and signature_raw:
            publisher = self.repo.get_publisher(publisher_id)
            if not publisher:
                raise IngestError("unknown_publisher", 404)
            if publisher["status"] != "active":
                raise IngestError("publisher_revoked")
            sig_bytes = parse_signature(signature_raw)
            if sig_bytes is None:
                raise IngestError("invalid_signature_format")
            pub_bytes = bytes.fromhex(publisher["public_key"])
            if not verify_ed25519(pub_bytes, content_hash.encode("ascii"), sig_bytes):
                raise IngestError("signature_verification_failed")
            canonical_sig = sig_bytes.hex()
            signature_verified = True
            verified_at = NOW()

        existing = self.repo.find_release(asset_id=asset_id, version=version,
                                          content_hash=content_hash)
        if existing:
            return {"release": asset_release_from_row(existing).model_dump(mode="json"),
                "duplicate": True}
        model = AssetRelease(release_id=new_release_id(), asset_id=asset_id,
                             version=version, content_hash=content_hash,
                             source_uri=_text(body.get("source_uri"), "source_uri",
                                              maximum=500),
                             publisher_id=publisher_id,
                             signature=canonical_sig,
                             signature_verified=signature_verified,
                             verified_at=verified_at,
                             published_at=published)
        return {"release": self.repo.create_release(model).model_dump(mode="json"),
                "duplicate": False}

    # ---------- 查询 ----------

    def _admissions_for_instances(self, instance_ids: list[str]) -> dict[str, list[dict]]:
        if not instance_ids:
            return {}
        marks = ",".join("?" * len(instance_ids))
        with self.storage.connection() as conn:
            rows = conn.execute(
                f"SELECT * FROM admissions WHERE asset_instance_id IN ({marks})"
                " ORDER BY updated_at DESC",
                instance_ids,
            ).fetchall()
        grouped: dict[str, list[dict]] = {}
        for row in rows:
            grouped.setdefault(row["asset_instance_id"], []).append(dict(row))
        return grouped

    def _executions_for_instances(self, instance_ids: list[str]) -> dict[str, list[dict]]:
        if not instance_ids:
            return {}
        marks = ",".join("?" * len(instance_ids))
        with self.storage.connection() as conn:
            rows = conn.execute(
                f"SELECT * FROM executions WHERE asset_instance_id IN ({marks})"
                " ORDER BY started_at DESC",
                instance_ids,
            ).fetchall()
        grouped: dict[str, list[dict]] = {}
        for row in rows:
            grouped.setdefault(row["asset_instance_id"], []).append(dict(row))
        return grouped

    def _instance_view(self, row: dict[str, Any],
                       admissions: dict[str, list[dict]],
                       executions: dict[str, list[dict]]) -> dict[str, Any]:
        instance_id = row["instance_id"]
        view = dict(row)
        view["installation_state"] = derive_installation_state(
            admissions.get(instance_id, []))
        view["activation_state"] = derive_activation_state(admissions.get(instance_id, []))
        view["runtime_state"] = derive_runtime_state(executions.get(instance_id, []))
        view["admission_count"] = len(admissions.get(instance_id, []))
        view["execution_count"] = len(executions.get(instance_id, []))
        return view

    def list_assets(self, *, limit: int = 100, asset_type: str | None = None,
                    product: str | None = None, host_id: str | None = None,
                    installation_state: str | None = None,
                    runtime_state: str | None = None,
                    activation_state: str | None = None,
                    query: str | None = None) -> dict[str, Any]:
        if asset_type:
            AssetType(asset_type)
        rows = self.repo.list_assets(limit=limit, asset_type=asset_type, product=product,
                                     query=query)
        candidates = {row["asset_id"] for row in rows}
        instances = self.repo.list_instances(host_id=host_id, limit=1000)
        by_asset: dict[str, list[dict]] = {}
        for row in instances:
            if row["asset_id"] in candidates:
                by_asset.setdefault(row["asset_id"], []).append(row)

        instance_ids = [row["instance_id"] for group in by_asset.values() for row in group]
        admissions = self._admissions_for_instances(instance_ids)
        executions = self._executions_for_instances(instance_ids)

        items = []
        for row in rows:
            views = [self._instance_view(item, admissions, executions)
                     for item in by_asset.get(row["asset_id"], [])]
            # host_id 是资产级过滤条件：该资产在指定主机上没有副本就不出现在
            # 结果里。只把 instances 收窄而照样返回资产，等于把"这台主机上有
            # 什么"显示成"全部资产（大多未登记副本）"——和不忽略参数相比，
            # 后者更容易被读成"这些资产都在这台主机上"。
            if host_id and not views:
                continue
            for name, wanted in (("installation_state", installation_state),
                                 ("runtime_state", runtime_state),
                                 ("activation_state", activation_state)):
                if wanted and not any(view[name] == wanted for view in views):
                    break
            else:
                items.append({"asset": asset_from_row(row).model_dump(mode="json"),
                              "instances": views})
        return {"items": items, "links": TRACE_LINKS}

    def trace(self, asset_id: str) -> dict[str, Any]:
        row = self.repo.get_asset(asset_id)
        if not row:
            raise IngestError("unknown_asset", 404)
        releases = self.repo.list_releases(asset_id)
        instances = self.repo.list_instances(asset_id=asset_id)
        instance_ids = [item["instance_id"] for item in instances]
        admissions = self._admissions_for_instances(instance_ids)
        executions = self._executions_for_instances(instance_ids)

        admission_rows = [item for group in admissions.values() for item in group]
        execution_rows = [item for group in executions.values() for item in group]
        admission_ids = [item["admission_id"] for item in admission_rows]
        execution_ids = [item["execution_id"] for item in execution_rows]

        with self.storage.connection() as conn:
            findings = [dict(r) for r in conn.execute(
                "SELECT * FROM findings WHERE asset_id = ?", (asset_id,)).fetchall()]
            linked = [dict(r) for r in conn.execute(
                "SELECT f.*, l.actor_id AS linked_by, l.note AS link_note,"
                " l.created_at AS linked_at FROM execution_findings l"
                " JOIN findings f ON f.finding_id = l.finding_id"
                " WHERE l.execution_id IN (%s)" % ",".join("?" * len(execution_ids)),
                execution_ids).fetchall()] if execution_ids else []
            seen = {item["finding_id"] for item in findings}
            for item in linked:
                if item["finding_id"] not in seen:
                    findings.append(item)
                    seen.add(item["finding_id"])
            finding_ids = [item["finding_id"] for item in findings]

            subjects = [asset_id, *instance_ids, *finding_ids, *execution_ids, *admission_ids]
            decisions = []
            if subjects:
                decisions = [dict(r) for r in conn.execute(
                    "SELECT * FROM policy_decisions WHERE subject_id IN (%s)"
                    " ORDER BY created_at DESC" % ",".join("?" * len(subjects)),
                    subjects).fetchall()]

            evidence_ids = [*finding_ids, *execution_ids]
            incidents = []
            if evidence_ids:
                incidents = [dict(r) for r in conn.execute(
                    "SELECT i.*, GROUP_CONCAT(e.evidence_kind || ':' || e.evidence_id)"
                    " AS evidence FROM incident_evidence e JOIN incidents i"
                    " ON i.incident_id = e.incident_id"
                    " WHERE e.evidence_id IN (%s) GROUP BY i.incident_id"
                    " ORDER BY i.updated_at DESC" % ",".join("?" * len(evidence_ids)),
                    evidence_ids).fetchall()]

        return {
            "asset": asset_from_row(row).model_dump(mode="json"),
            "releases": [asset_release_from_row(item).model_dump(mode="json")
                        for item in releases],
            "instances": [self._instance_view(item, admissions, executions)
                          for item in instances],
            "admissions": admission_rows,
            "executions": execution_rows,
            "findings": findings,
            "policy_decisions": decisions,
            "incidents": incidents,
            "links": TRACE_LINKS,
        }

    # ---------- 执行 ↔ 发现项 ----------

    def link_execution_finding(self, execution_id: str, body: dict[str, Any],
                               actor_id: str) -> dict[str, Any]:
        reject_secrets(body)
        if set(body) - {"finding_id", "note"}:
            raise IngestError("invalid_execution_finding_input")
        finding_id = _text(body.get("finding_id"), "finding_id", maximum=64, required=True)
        note = _text(body.get("note"), "note", maximum=500)
        with self.storage.connection() as conn:
            if not conn.execute("SELECT 1 FROM executions WHERE execution_id = ?",
                                (execution_id,)).fetchone():
                raise IngestError("unknown_execution", 404)
            if not conn.execute("SELECT 1 FROM findings WHERE finding_id = ?",
                                (finding_id,)).fetchone():
                raise IngestError("unknown_finding", 404)
        created = self.repo.link_execution_finding(execution_id=execution_id,
                                                   finding_id=finding_id, actor_id=actor_id,
                                                   note=note or "")
        return {"execution_id": execution_id, "finding_id": finding_id,
                "linked": created, "actor_id": actor_id,
                "association": "analyst_linked"}
