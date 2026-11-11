"""产品适配器集合。"""

from adapters.products.base import (
    AgentProductAdapter,
    HookDirective,
    HookEvent,
    HookResponse,
    UnsupportedHookProtocol,
)
from adapters.products.claude_code import ClaudeCodeAdapter
from adapters.products.codex import CodexAdapter

__all__ = [
    "AgentProductAdapter",
    "ClaudeCodeAdapter",
    "CodexAdapter",
    "HookDirective",
    "HookEvent",
    "HookResponse",
    "UnsupportedHookProtocol",
]
