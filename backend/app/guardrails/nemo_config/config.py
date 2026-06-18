from __future__ import annotations

import re
from typing import Optional

from nemoguardrails import LLMRails
from nemoguardrails.actions import action


_INPUT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bignore\s+(all\s+)?previous\s+instructions?\b", re.I),
    re.compile(r"\b(repeat|reveal|print|show)\b.*\b(system|hidden|developer)\s+prompt\b", re.I),
    re.compile(r"\b(from now on|you are now|act as|pretend to be)\b.{0,120}\b(system\s+developer|developer|admin(?:istrator)?|auditor)\b", re.I),
    re.compile(r"\bdisable\s+safety\s+rules?\b|\bdisable\s+all\s+guardrails?\b", re.I),
    re.compile(r"\b(retrieved|knowledge\s+base|document|context|chunk|web\s+page)\b.{0,160}\b(ignore|override|export|use\s+the\s+retrieved\s+instruction)\b", re.I),
    re.compile(r"\b(call|use|run)\b.{0,80}\b(export_internal_reports|export_data|admin\s+export)\b.{0,120}\b(role\s*=\s*admin|bypass|authorization|auth|public)\b", re.I),
    re.compile(r"\b(add|generate|create|write|provide)\b.{0,80}\b(paraphrase(?:d)?|multi-turn|translated|translation)\b.{0,120}\b(variants?|probes?|payloads?|attack\s+set)\b", re.I),
)

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
    return not any(pattern.search(text) for pattern in _INPUT_PATTERNS)


@action(is_system_action=True)
async def llmsec_check_output(context: Optional[dict] = None, **_: object) -> bool:
    text = _text_from_context(context, "bot_message")
    return not any(pattern.search(text) for pattern in _OUTPUT_PATTERNS)


def init(app: LLMRails) -> None:
    app.register_action(llmsec_check_input, "llmsec_check_input")
    app.register_action(llmsec_check_output, "llmsec_check_output")
