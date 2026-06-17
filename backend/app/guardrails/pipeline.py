from __future__ import annotations

import re
from enum import Enum

from app.schemas.security import GuardAction, GuardResult, GuardStage


class GuardMode(str, Enum):
    ENFORCE = "enforce"
    AUDIT = "audit"
    OFF = "off"


class GuardEngine(str, Enum):
    CUSTOM = "custom"
    NEMO = "nemo"
    CUSTOM_NEMO = "custom_nemo"


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
        (
            "role_takeover_authority_claim",
            re.compile(
                r"\b(from now on|you are now|act as|pretend to be)\b.{0,120}"
                r"\b(system\s+developer|developer|admin(?:istrator)?|auditor)\b"
                r"|\bdisable\s+safety\s+rules?\b",
                re.I,
            ),
            "Detected role reassignment or safety-disabling attempt.",
            0.92,
        ),
        (
            "rag_policy_override",
            re.compile(
                r"\b(retrieved|document|context|chunk)\b.{0,120}"
                r"\b(says|instructs|asks|contains|tells)\b.{0,120}"
                r"\boverride\s+policy\b",
                re.I,
            ),
            "Detected untrusted retrieved content attempting to override policy.",
            0.92,
        ),
        (
            "rag_source_instruction_override",
            re.compile(
                r"\b(retrieved|knowledge\s+base|document|context|chunk)\b.{0,160}"
                r"\b(says|instructs|asks|contains|tells)\b.{0,160}"
                r"\b(ignore|override|export|use\s+the\s+retrieved\s+instruction)\b"
                r"|\buse\s+the\s+retrieved\s+instruction\b",
                re.I,
            ),
            "Detected untrusted retrieved content attempting to issue instructions.",
            0.91,
        ),
        (
            "tool_output_instruction_injection",
            re.compile(
                r"\b(tool\s+(returned|result|output)|api\s+response)\b.{0,160}"
                r"\b(new\s+instruction|ignore|call\s+the\s+admin|export)\b",
                re.I,
            ),
            "Detected tool output attempting to issue follow-up instructions.",
            0.9,
        ),
        (
            "public_role_export_request",
            re.compile(
                r"\b(call|use|run)\b.{0,80}\bexport\s+tool\b.{0,140}"
                r"\b(role\s+is\s+public|public\s+role|even\s+though.{0,60}public)\b",
                re.I,
            ),
            "Detected export tool request that conflicts with a public caller role.",
            0.9,
        ),
        (
            "unauthorized_tool_escalation",
            re.compile(
                r"\b(call|use|run)\b.{0,80}"
                r"\b(export_internal_reports|export_data|admin\s+export)\b.{0,120}"
                r"\b(role\s*=\s*admin|bypass|authorization|auth)\b",
                re.I,
            ),
            "Detected unauthorized sensitive tool escalation attempt.",
            0.93,
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

    _NEMO_INPUT_RULES: tuple[tuple[str, re.Pattern[str], str, float], ...] = (
        (
            "nemo_prompt_injection",
            re.compile(r"\b(ignore|bypass|override)\b.*\b(instruction|policy|rule)s?\b", re.I),
            "NeMo-compatible lane detected an instruction override attempt.",
            0.91,
        ),
        (
            "nemo_system_prompt_leak",
            re.compile(r"\b(system|developer|hidden)\s+(prompt|instruction|message)s?\b", re.I),
            "NeMo-compatible lane detected prompt secrecy risk.",
            0.89,
        ),
        (
            "nemo_tool_abuse",
            re.compile(r"\b(call|use|run)\b.*\b(export_data|admin|bypass|authorization)\b", re.I),
            "NeMo-compatible lane detected tool abuse risk.",
            0.88,
        ),
    )

    def __init__(
        self,
        mode: GuardMode = GuardMode.ENFORCE,
        engine: GuardEngine = GuardEngine.CUSTOM,
    ) -> None:
        self.mode = mode
        self.engine = engine

    def check_input(self, text: str) -> GuardResult:
        if self.engine == GuardEngine.NEMO:
            return self._check_rules(
                GuardStage.PRE_INPUT,
                text,
                self._NEMO_INPUT_RULES,
                engine=GuardEngine.NEMO,
                engines_checked=[GuardEngine.NEMO.value],
            )
        if self.engine == GuardEngine.CUSTOM_NEMO:
            custom = self._check_rules(
                GuardStage.PRE_INPUT,
                text,
                self._INPUT_RULES,
                engine=GuardEngine.CUSTOM_NEMO,
                engines_checked=[GuardEngine.CUSTOM.value, GuardEngine.NEMO.value],
            )
            if custom.triggered:
                return custom
            return self._check_rules(
                GuardStage.PRE_INPUT,
                text,
                self._NEMO_INPUT_RULES,
                engine=GuardEngine.CUSTOM_NEMO,
                engines_checked=[GuardEngine.CUSTOM.value, GuardEngine.NEMO.value],
            )
        return self._check_rules(
            GuardStage.PRE_INPUT,
            text,
            self._INPUT_RULES,
            engine=GuardEngine.CUSTOM,
            engines_checked=[GuardEngine.CUSTOM.value],
        )

    def check_output(self, text: str) -> GuardResult:
        return self._check_rules(
            GuardStage.POST_OUTPUT,
            text,
            self._OUTPUT_RULES,
            engine=self.engine,
            engines_checked=[self.engine.value],
        )

    def _check_rules(
        self,
        stage: GuardStage,
        text: str,
        rules: tuple[tuple[str, re.Pattern[str], str, float], ...],
        *,
        engine: GuardEngine,
        engines_checked: list[str],
    ) -> GuardResult:
        if self.mode == GuardMode.OFF:
            return self._allow(stage, engine=engine, engines_checked=engines_checked)

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
                metadata={
                    "matched_text": match.group(0),
                    "guard_engine": engine.value,
                    "engines_checked": engines_checked,
                },
            )

        return self._allow(stage, engine=engine, engines_checked=engines_checked)

    def _trigger_action(self) -> GuardAction:
        if self.mode == GuardMode.AUDIT:
            return GuardAction.AUDIT
        return GuardAction.BLOCK

    @staticmethod
    def _allow(stage: GuardStage, *, engine: GuardEngine, engines_checked: list[str]) -> GuardResult:
        return GuardResult(
            stage=stage,
            rule_name="no_match",
            triggered=False,
            confidence=0.0,
            action=GuardAction.ALLOW,
            reason="No guardrail rule matched.",
            metadata={
                "guard_engine": engine.value,
                "engines_checked": engines_checked,
            },
        )
