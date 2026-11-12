"""Pytest 配置：把 backend/ 加入 sys.path，使领域包可按目录名导入。

同时在这里禁止任何测试启动真实的 Agent 产品 CLI（claude / codex / qwen）。

理由不是洁癖：控制面主机上通常装着开发主力的 Agent，一次无关的测试就可能
在别人的开发环境里起会话、写 transcript、消耗模型额度，甚至改产品配置。
测试要验证的是"我们怎么判定产品加载"，不是"真的把产品跑起来"；需要真实
产品的地方一律显式注入假实现。
"""

import sys
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parent / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))


@pytest.fixture(autouse=True)
def _never_start_product_cli(monkeypatch):
    """默认禁用产品 CLI 探测；需要模拟的测试自己再 patch 覆盖。"""
    from services import product_installer

    monkeypatch.setattr(
        product_installer,
        "_resolve_command",
        lambda name, home: None,
        raising=True,
    )
    yield
