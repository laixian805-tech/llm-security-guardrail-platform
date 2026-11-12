"""一致性守卫：版本号只有一个真值，硬编码不回流。

来历：本项目踩过两次同类坑——
1. 测试把 ``schema_version == "8"`` 写死，schema 升到 v9 就红；
2. ``ADAPTER_VERSION = "1.0.0"`` 定义了却没人引用，descriptor 里另写 ``"1.1.0"``，
   改常量不生效。

两次都是"修一处、没扫全场"的直接后果。所以这里不只断言当前值，而是把
``scripts/lab/scan_hardcoded.py`` 挂进测试：以后任何新写的硬编码/重复真值
都会让回归变红，而不是等人发现。
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "scripts" / "lab" / "scan_hardcoded.py"


@pytest.fixture(scope="module")
def capabilities():
    sys.path.insert(0, str(ROOT / "backend"))
    from adapters.products import capabilities as module
    return module


def test_adapter_version_is_single_source(capabilities):
    """所有产品的 descriptor 必须报同一个适配器版本常量。"""
    assert capabilities.PRODUCT_CAPABILITIES, "产品能力矩阵不能为空"
    for product_id, descriptor in capabilities.PRODUCT_CAPABILITIES.items():
        assert descriptor.adapter_version == capabilities.ADAPTER_VERSION, (
            f"{product_id} 的 adapter_version 与常量不一致："
            f"{descriptor.adapter_version} != {capabilities.ADAPTER_VERSION}"
        )


def test_product_versions_come_from_constant(capabilities):
    """产品版本必须取自 PRODUCT_VERSIONS，不能在 descriptor 里另写。"""
    for product_id, descriptor in capabilities.PRODUCT_CAPABILITIES.items():
        assert product_id in capabilities.PRODUCT_VERSIONS, f"{product_id} 缺少版本常量"
        assert descriptor.product_version == capabilities.PRODUCT_VERSIONS[product_id], (
            f"{product_id} 声明版本 {descriptor.product_version} 与常量 "
            f"{capabilities.PRODUCT_VERSIONS[product_id]} 不一致"
        )


def test_schema_version_matches_migration_chain():
    """库内记录的版本必须等于代码里的 SCHEMA_VERSION。"""
    sys.path.insert(0, str(ROOT / "backend"))
    from storage.schema import SCHEMA_VERSION
    import tempfile
    from storage.repositories import Storage

    with tempfile.TemporaryDirectory() as tmp:
        storage = Storage(Path(tmp) / "schema.db")
        with storage.connection() as conn:
            recorded = conn.execute(
                "SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0]
    assert recorded == str(SCHEMA_VERSION), (
        f"库内 schema_version={recorded} 与代码常量 {SCHEMA_VERSION} 不一致："
        "迁移链末端没调用最新的 _migrate_vN"
    )


def test_hardcoded_scanner_is_clean():
    """硬编码扫描必须零发现；发现任何一项都说明真值又散开了。"""
    completed = subprocess.run([sys.executable, str(SCANNER), "--json"],
                               capture_output=True, text=True, timeout=120)
    assert completed.returncode in (0, 1), completed.stderr
    report = json.loads(completed.stdout)
    assert report["ok"], (
        "扫描器报出硬编码/重复真值："
        + json.dumps(report["findings"], ensure_ascii=False, indent=1)
    )
