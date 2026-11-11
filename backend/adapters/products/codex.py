"""Codex 0.166.0 原生 Hook，字段依据测试机真实派发 fixture。"""
from adapters.products.claude_code import ClaudeCodeAdapter
from adapters.products.capabilities import PRODUCT_CAPABILITIES
from adapters.products.base import UnsupportedHookProtocol
from domain import IntentDecision


class CodexAdapter(ClaudeCodeAdapter):
    def descriptor(self):
        return PRODUCT_CAPABILITIES['codex']

    def _render_decision(self, event, directive):
        if directive.decision is IntentDecision.ASK:
            raise UnsupportedHookProtocol("Codex 0.166.0 ignores ask; confirmation is unsupported")
        return super()._render_decision(event, directive)
