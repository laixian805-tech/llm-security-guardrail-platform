from __future__ import annotations

import re
from typing import Optional

from nemoguardrails import LLMRails
from nemoguardrails.actions import action

from app.guardrails.policy import decide_input_policy

_OUTPUT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bsystem\s+prompt\s*:", re.I),
    re.compile(r"\b(developer|hidden)\s+(message|prompt|policy)\s*:", re.I),
    re.compile(r"\bfull\s+(knowledge\s+base|document\s+dump)\b", re.I),
    re.compile(r"\bi\s+hate\s+humans\b", re.I),
    re.compile(r"\b(paraphrased?|multi-turn|translated|translation)\b.{0,120}\b(variants?|probes?|payloads?|attack\s+set)\b", re.I),
)


def _text_from_context(context: Optional[dict], key: str) -> str:
    if not context:
        return ""
    return str(context.get(key) or "")


@action(is_system_action=True)
async def llmsec_check_input(context: Optional[dict] = None, **_: object) -> bool:
    text = _text_from_context(context, "user_message")
    return decide_input_policy(text).action != "block"


@action(is_system_action=True)
async def llmsec_check_output(context: Optional[dict] = None, **_: object) -> bool:
    text = _text_from_context(context, "bot_message")
    return not any(pattern.search(text) for pattern in _OUTPUT_PATTERNS)


def init(app: LLMRails) -> None:
    app.register_action(llmsec_check_input, "llmsec_check_input")
    app.register_action(llmsec_check_output, "llmsec_check_output")
