"""产品目录：product_id 到适配器的映射。

增删产品只改这里的注册表，不改摄入与查询服务。
"""

from __future__ import annotations

from adapters.products import ClaudeCodeAdapter, CodexAdapter, QwenCodeAdapter
from adapters.products.base import AgentProductAdapter

ADAPTER_TYPES = {
    "claude-code": ClaudeCodeAdapter,
    "codex": CodexAdapter,
    "qwen-code": QwenCodeAdapter,
}


class ProductCatalog:
    """按需构造适配器实例；未注册的 product_id 一律拒绝。"""

    def __init__(self) -> None:
        self._cache: dict[str, AgentProductAdapter] = {}

    def ids(self) -> list[str]:
        return sorted(ADAPTER_TYPES)

    def get(self, product_id: str) -> AgentProductAdapter:
        adapter_type = ADAPTER_TYPES.get(product_id)
        if adapter_type is None:
            raise KeyError(product_id)
        cached = self._cache.get(product_id)
        if cached is None:
            cached = adapter_type()
            self._cache[product_id] = cached
        return cached

    def descriptor(self, product_id: str):
        return self.get(product_id).descriptor()

    def descriptors(self) -> list:
        return [self.get(product_id).descriptor() for product_id in self.ids()]
