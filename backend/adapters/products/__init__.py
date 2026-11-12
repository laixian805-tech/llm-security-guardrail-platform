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
from adapters.products.qwen_code import QwenCodeAdapter

__all__ = [
    "AgentProductAdapter",
    "ClaudeCodeAdapter",
    "CodexAdapter",
    "QwenCodeAdapter",
    "HookDirective",
    "HookEvent",
    "HookResponse",
    "UnsupportedHookProtocol",
]
