"""资产台账仓储：Asset / AssetInstance / AssetRelease 与执行-发现项关联。

台账只登记平台自己持有的证据：谁在什么时候登记了哪个逻辑资产、哪个副本、
哪个内容版本。安装/启用/运行三态不落库——它们由 AssetService 按准入事务和
执行记录现算，客户端声明不进入存储，否则"看起来已安装"会被当成已安装。

executions/admissions 里的 asset_instance_id 是 P1 遗留的自由文本，没有外键。
台账不回溯校验这些引用：查得到就呈现，查不到就按未登记处理，不猜。
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from domain import Asset, AssetInstance, AssetRelease, Publisher
from storage.repositories import Storage, now_iso


def _parse_iso(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def asset_from_row(row: dict[str, Any]) -> Asset:
    return Asset(
        asset_id=row["asset_id"],
        asset_type=row["asset_type"],
        canonical_name=row["canonical_name"],
        product=row["product"],
        publisher=row["publisher"],
        namespace=row["namespace"],
        provenance=row["provenance"],
        created_at=datetime.fromisoformat(row["created_at"]),
        updated_at=datetime.fromisoformat(row["updated_at"]),
    )


def asset_instance_from_row(row: dict[str, Any]) -> AssetInstance:
    # 三态不落库：登记请求不接受这些字段，查询时的取值由 AssetService 现算后盖在
    # 视图上，所以这里不读行里的任何状态列。
    return AssetInstance(
        instance_id=row["instance_id"],
        asset_id=row["asset_id"],
        host_id=row["host_id"],
        product_scope=row["product_scope"],
        install_path=row["install_path"],
        first_seen_at=datetime.fromisoformat(row["first_seen_at"]),
        last_seen_at=datetime.fromisoformat(row["last_seen_at"]),
    )


def publisher_from_row(row: dict[str, Any]) -> Publisher:
    return Publisher(
        publisher_id=row["publisher_id"],
        name=row["name"],
        public_key=row["public_key"],
        algorithm=row["algorithm"],
        status=row["status"],
        created_at=datetime.fromisoformat(row["created_at"]),
        revoked_at=_parse_iso(row["revoked_at"]),
    )


def asset_release_from_row(row: dict[str, Any]) -> AssetRelease:
    return AssetRelease(
        release_id=row["release_id"],
        asset_id=row["asset_id"],
        version=row["version"],
        content_hash=row["content_hash"],
        source_uri=row["source_uri"],
        publisher_id=row.get("publisher_id"),
        signature=row.get("signature"),
        signature_verified=bool(row["signature_verified"]),
        verified_at=_parse_iso(row.get("verified_at")),
        published_at=_parse_iso(row["published_at"]),
    )


class AssetRepository:
    def __init__(self, storage: Storage) -> None:
        self._storage = storage

    # ---------- Asset ----------

    def create_asset(self, model: Asset) -> Asset:
        with self._storage._lock, self._storage.connection() as conn:
            conn.execute(
                "INSERT INTO assets (asset_id, asset_type, canonical_name, product, publisher,"
                " namespace, provenance, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (model.asset_id, model.asset_type.value, model.canonical_name, model.product,
                 model.publisher, model.namespace, model.provenance,
                 model.created_at.isoformat(), model.updated_at.isoformat()),
            )
        return model

    def get_asset(self, asset_id: str) -> dict[str, Any] | None:
        with self._storage.connection() as conn:
            row = conn.execute("SELECT * FROM assets WHERE asset_id = ?", (asset_id,)).fetchone()
        return dict(row) if row else None

    def find_asset_by_name(self, *, asset_type: str, canonical_name: str,
                           product: str | None) -> dict[str, Any] | None:
        """同名同类型同产品的逻辑资产只登记一次，重复登记返回原行。"""
        with self._storage.connection() as conn:
            row = conn.execute(
                "SELECT * FROM assets WHERE asset_type = ? AND canonical_name = ?"
                " AND product IS ?",
                (asset_type, canonical_name, product),
            ).fetchone()
        return dict(row) if row else None

    def list_assets(self, *, limit: int = 100, asset_type: str | None = None,
                    product: str | None = None, provenance: str | None = None,
                    query: str | None = None) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if asset_type:
            clauses.append("asset_type = ?")
            params.append(asset_type)
        if product:
            clauses.append("product = ?")
            params.append(product)
        if provenance:
            clauses.append("provenance = ?")
            params.append(provenance)
        if query:
            clauses.append("canonical_name LIKE ?")
            params.append(f"%{query}%")
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        with self._storage.connection() as conn:
            rows = conn.execute(
                f"SELECT * FROM assets{where} ORDER BY updated_at DESC LIMIT ?", params
            ).fetchall()
        return [dict(row) for row in rows]

    def touch_asset(self, asset_id: str) -> None:
        with self._storage._lock, self._storage.connection() as conn:
            conn.execute("UPDATE assets SET updated_at = ? WHERE asset_id = ?",
                         (now_iso(), asset_id))

    # ---------- AssetInstance ----------

    def create_instance(self, model: AssetInstance) -> AssetInstance:
        with self._storage._lock, self._storage.connection() as conn:
            conn.execute(
                "INSERT INTO asset_instances (instance_id, asset_id, host_id, product_scope,"
                " install_path, first_seen_at, last_seen_at) VALUES (?,?,?,?,?,?,?)",
                (model.instance_id, model.asset_id, model.host_id, model.product_scope,
                 model.install_path, model.first_seen_at.isoformat(),
                 model.last_seen_at.isoformat()),
            )
        return model

    def get_instance(self, instance_id: str) -> dict[str, Any] | None:
        with self._storage.connection() as conn:
            row = conn.execute(
                "SELECT * FROM asset_instances WHERE instance_id = ?", (instance_id,)
            ).fetchone()
        return dict(row) if row else None

    def find_instance(self, *, asset_id: str, host_id: str,
                      product_scope: str) -> dict[str, Any] | None:
        with self._storage.connection() as conn:
            row = conn.execute(
                "SELECT * FROM asset_instances WHERE asset_id = ? AND host_id = ?"
                " AND product_scope = ?",
                (asset_id, host_id, product_scope),
            ).fetchone()
        return dict(row) if row else None

    def list_instances(self, *, asset_id: str | None = None,
                       host_id: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if asset_id:
            clauses.append("asset_id = ?")
            params.append(asset_id)
        if host_id:
            clauses.append("host_id = ?")
            params.append(host_id)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        with self._storage.connection() as conn:
            rows = conn.execute(
                f"SELECT * FROM asset_instances{where} ORDER BY last_seen_at DESC LIMIT ?",
                params,
            ).fetchall()
        return [dict(row) for row in rows]

    def fill_install_path(self, *, instance_id: str, install_path: str) -> None:
        """只补空，不覆盖：已登记的安装路径不被重复上报改写。"""
        with self._storage._lock, self._storage.connection() as conn:
            conn.execute(
                "UPDATE asset_instances SET install_path = COALESCE(install_path, ?),"
                " last_seen_at = ? WHERE instance_id = ?",
                (install_path, now_iso(), instance_id),
            )

    def touch_instance(self, instance_id: str) -> None:
        with self._storage._lock, self._storage.connection() as conn:
            conn.execute("UPDATE asset_instances SET last_seen_at = ? WHERE instance_id = ?",
                         (now_iso(), instance_id))

    # ---------- Publisher ----------

    def create_publisher(self, model: Publisher) -> Publisher:
        with self._storage._lock, self._storage.connection() as conn:
            conn.execute(
                "INSERT INTO publishers (publisher_id, name, public_key, algorithm,"
                " status, created_at, revoked_at) VALUES (?,?,?,?,?,?,?)",
                (model.publisher_id, model.name, model.public_key, model.algorithm,
                 model.status, model.created_at.isoformat(),
                 model.revoked_at.isoformat() if model.revoked_at else None),
            )
        return model

    def get_publisher(self, publisher_id: str) -> dict[str, Any] | None:
        with self._storage.connection() as conn:
            row = conn.execute("SELECT * FROM publishers WHERE publisher_id = ?", (publisher_id,)).fetchone()
        return dict(row) if row else None

    def find_publisher_by_name(self, name: str) -> dict[str, Any] | None:
        with self._storage.connection() as conn:
            row = conn.execute("SELECT * FROM publishers WHERE name = ?", (name,)).fetchone()
        return dict(row) if row else None

    def list_publishers(self, *, limit: int = 100) -> list[dict[str, Any]]:
        with self._storage.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM publishers ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) for row in rows]

    def revoke_publisher(self, publisher_id: str) -> dict[str, Any] | None:
        with self._storage._lock, self._storage.connection() as conn:
            conn.execute(
                "UPDATE publishers SET status = 'revoked', revoked_at = COALESCE(revoked_at, ?)"
                " WHERE publisher_id = ?",
                (now_iso(), publisher_id),
            )
            row = conn.execute("SELECT * FROM publishers WHERE publisher_id = ?", (publisher_id,)).fetchone()
        return dict(row) if row else None

    # ---------- AssetRelease ----------

    def create_release(self, model: AssetRelease) -> AssetRelease:
        with self._storage._lock, self._storage.connection() as conn:
            conn.execute(
                "INSERT INTO asset_releases (release_id, asset_id, version, content_hash,"
                " source_uri, publisher_id, signature, signature_verified, verified_at,"
                " published_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (model.release_id, model.asset_id, model.version, model.content_hash,
                 model.source_uri, model.publisher_id, model.signature,
                 1 if model.signature_verified else 0,
                 model.verified_at.isoformat() if model.verified_at else None,
                 model.published_at.isoformat() if model.published_at else None),
            )
        return model

    def list_releases(self, asset_id: str) -> list[dict[str, Any]]:
        with self._storage.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM asset_releases WHERE asset_id = ?"
                " ORDER BY COALESCE(published_at, '') DESC, release_id",
                (asset_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def find_release(self, *, asset_id: str, version: str,
                     content_hash: str) -> dict[str, Any] | None:
        with self._storage.connection() as conn:
            row = conn.execute(
                "SELECT * FROM asset_releases WHERE asset_id = ? AND version = ?"
                " AND content_hash = ?",
                (asset_id, version, content_hash),
            ).fetchone()
        return dict(row) if row else None

    # ---------- 执行 ↔ 发现项 关联 ----------

    def link_execution_finding(self, *, execution_id: str, finding_id: str,
                               actor_id: str, note: str) -> bool:
        """登记一条分析员关联；已存在返回 False（不产生第二行）。"""
        with self._storage._lock, self._storage.connection() as conn:
            cursor = conn.execute(
                "INSERT OR IGNORE INTO execution_findings (execution_id, finding_id, actor_id,"
                " note, created_at) VALUES (?,?,?,?,?)",
                (execution_id, finding_id, actor_id, note, now_iso()),
            )
            return cursor.rowcount == 1

    def findings_for_execution(self, execution_id: str) -> list[dict[str, Any]]:
        with self._storage.connection() as conn:
            rows = conn.execute(
                "SELECT f.*, l.actor_id AS linked_by, l.note AS link_note,"
                " l.created_at AS linked_at FROM execution_findings l"
                " JOIN findings f ON f.finding_id = l.finding_id"
                " WHERE l.execution_id = ? ORDER BY l.created_at, f.finding_id",
                (execution_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def executions_for_finding(self, finding_id: str) -> list[dict[str, Any]]:
        with self._storage.connection() as conn:
            rows = conn.execute(
                "SELECT e.* FROM execution_findings l"
                " JOIN executions e ON e.execution_id = l.execution_id"
                " WHERE l.finding_id = ? ORDER BY e.started_at DESC",
                (finding_id,),
            ).fetchall()
        return [dict(row) for row in rows]


def new_asset_id() -> str:
    return f"asset_{uuid.uuid4().hex[:16]}"


def new_instance_id() -> str:
    return f"inst_{uuid.uuid4().hex[:16]}"


def new_release_id() -> str:
    return f"rel_{uuid.uuid4().hex[:16]}"


def new_publisher_id() -> str:
    return f"pub_{uuid.uuid4().hex[:16]}"
