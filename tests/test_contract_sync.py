"""契约同步测试。

契约以 Pydantic 模型为唯一事实来源，`contracts/*.schema.json` 是给外部集成
和前端使用的固定视图。改了契约忘了重新导出，下游拿到的就是过期 schema，
所以这里直接把内存中的导出结果和已提交的文件逐一比对。
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts"

_spec = importlib.util.spec_from_file_location(
    "export_schemas", ROOT / "scripts" / "export-schemas.py"
)
export_schemas = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(export_schemas)


@pytest.mark.parametrize("name", sorted(export_schemas.SCHEMAS))
def test_committed_schema_matches_pydantic_model(name):
    model = export_schemas.SCHEMAS[name]
    path = CONTRACTS / f"{name}.schema.json"
    assert path.is_file(), f"{path.name} 缺失，请运行 scripts/export-schemas.py"
    assert json.loads(path.read_text(encoding="utf-8")) == model.model_json_schema()


def test_every_committed_schema_is_exported():
    """contracts/ 里不该有导出脚本已经不认识的孤儿文件。"""
    exported = {f"{name}.schema.json" for name in export_schemas.SCHEMAS}
    on_disk = {path.name for path in CONTRACTS.glob("*.schema.json")}
    assert on_disk == exported
