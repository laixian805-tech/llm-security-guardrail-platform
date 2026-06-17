from __future__ import annotations

import re
from enum import Enum

from app.schemas.security import GuardAction, GuardResult, GuardStage


class GuardMode(str, Enum):
    ENFORCE = "enforce"
    AUDIT = "audit"
    OFF = "off"


class GuardrailPipeline:
    """Layered guardrail checks with enforce/audit/off modes."""

    _INPUT_RULES: tuple[tuple[str, re.Pattern[str], str, float], ...] = (
        (
            "prompt_injection_ignore_previous",
            re.compile(r"\bignore\s+(all\s+)?previous\s+instructions?\b", re.I),
            "Detected instruction override attempt.",
            0.95,
        ),
        (
            "system_prompt_extraction_request",
            re.compile(r"\b(repeat|reveal|print|show)\b.*\b(system|hidden)\s+prompt\b", re.I),
            "Detected system prompt extraction attempt.",
            0.93,
        ),
        (
            "rag_dump_request",
            re.compile(r"\b(output|dump|print|show)\b.*\b(all|entire|whole)\b.*\b(knowledge\s+base|documents?|context)\b", re.I),
            "Detected bulk knowledge-base extraction attempt.",
            0.9,
        ),
    )

    _OUTPUT_RULES: tuple[tuple[str, re.Pattern[str], str, float], ...] = (
        (
            "system_prompt_leak_output",
            re.compile(r"\bsystem\s+prompt\s*:", re.I),
            "Detected possible system prompt leakage in model output.",
            0.96,
        ),
        (
            "bulk_rag_dump_output",
            re.compile(r"\bfull\s+(knowledge\s+base|document\s+dump)\b", re.I),
            "Detected possible bulk RAG content dump.",
            0.88,
        ),
    )

    def __init__(self, mode: GuardMode = GuardMode.ENFORCE) -> None:
        self.mode = mode

    def check_input(self, text: str) -> GuardResult:
        return self._check_rules(GuardStage.PRE_INPUT, text, self._INPUT_RULES)

    def check_output(self, text: str) -> GuardResult:
        return self._check_rules(GuardStage.POST_OUTPUT, text, self._OUTPUT_RULES)

    def _check_rules(
        self,
        stage: GuardStage,
        text: str,
        rules: tuple[tuple[str, re.Pattern[str], str, float], ...],
    ) -> GuardResult:
        if self.mode == GuardMode.OFF:
            return self._allow(stage)

        for rule_name, pattern, reason, confidence in rules:
            match = pattern.search(text)
            if match is None:
                continue
            return GuardResult(
                stage=stage,
                rule_name=rule_name,
                triggered=True,
                confidence=confidence,
                action=self._trigger_action(),
                reason=reason,
                metadata={"matched_text": match.group(0)},
            )

        return self._allow(stage)

    def _trigger_action(self) -> GuardAction:
        if self.mode == GuardMode.AUDIT:
            return GuardAction.AUDIT
        return GuardAction.BLOCK

    @staticmethod
    def _allow(stage: GuardStage) -> GuardResult:
        return GuardResult(
            stage=stage,
            rule_name="no_match",
            triggered=False,
            confidence=0.0,
            action=GuardAction.ALLOW,
            reason="No guardrail rule matched.",
        )
