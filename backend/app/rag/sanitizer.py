from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field

from app.guardrails.pipeline import GuardMode, GuardrailPipeline
from app.rag.service import RetrievedChunk
from app.schemas.security import GuardAction, GuardResult, GuardStage


_LOW_TRUST_LEVELS = {"low", "unknown", "untrusted"}
_LOW_TRUST_SOURCES = {"user_upload", "web", "web_crawl", "external_api"}
_IMPERATIVE_PATTERN = re.compile(
    r"\b(ignore|override|bypass|disable|call|export|send|reveal|print|repeat)\b"
    r".{0,120}\b(instruction|policy|rule|system|admin|export_data|salary|audit|secret)\b",
    re.I,
)


class SanitizedChunk(BaseModel):
    chunk: dict[str, Any]
    isolated: bool
    reason: str | None = None
    guard_result: GuardResult | None = None


class SanitizedRAGContext(BaseModel):
    sanitized_context: str
    safe_chunks: list[dict[str, Any]] = Field(default_factory=list)
    poisoned_chunks: list[dict[str, Any]] = Field(default_factory=list)
    isolated_chunks: list[dict[str, Any]] = Field(default_factory=list)
    guard_result: GuardResult


def sanitize_retrieved_context(
    *,
    chunks: list[RetrievedChunk],
    pipeline: GuardrailPipeline | None = None,
) -> SanitizedRAGContext:
    pipeline = pipeline or GuardrailPipeline(mode=GuardMode.ENFORCE)
    safe_chunks: list[dict[str, Any]] = []
    poisoned_chunks: list[dict[str, Any]] = []
    isolated_chunks: list[dict[str, Any]] = []
    context_parts: list[str] = []
    first_guard_result: GuardResult | None = None

    for chunk in chunks:
        chunk_payload = chunk.model_dump(mode="json")
        metadata = chunk_payload.setdefault("metadata", {})
        low_trust = _is_low_trust(metadata)
        imperative = bool(_IMPERATIVE_PATTERN.search(chunk.text))
        if low_trust and imperative:
            guard_result = GuardResult(
                stage=GuardStage.PRE_INPUT,
                rule_name="rag_context_sanitizer_low_trust_instruction",
                triggered=True,
                confidence=0.88,
                action=GuardAction.BLOCK,
                reason="Low-trust retrieved content contained imperative instructions.",
                metadata={
                    "document_id": chunk.document_id,
                    "collection": metadata.get("collection"),
                    "trust_level": metadata.get("trust_level"),
                    "source_type": metadata.get("source_type"),
                    "guard_engine": "rag_context_sanitizer",
                },
            )
        elif low_trust:
            guard_result = pipeline.check_input(chunk.text)
        else:
            guard_result = GuardResult(
                stage=GuardStage.PRE_INPUT,
                rule_name="trusted_context_no_check",
                triggered=False,
                confidence=0.0,
                action=GuardAction.ALLOW,
                reason="Trusted retrieved content did not require model guardrail inspection.",
                metadata={
                    "document_id": chunk.document_id,
                    "collection": metadata.get("collection"),
                    "trust_level": metadata.get("trust_level"),
                    "source_type": metadata.get("source_type"),
                },
            )
        isolated = guard_result.action.value == "block"
        metadata["entered_model_context"] = not isolated
        if isolated:
            metadata["isolation_reason"] = (
                guard_result.reason
                if guard_result.action.value == "block"
                else "Low-trust retrieved content contained imperative instructions."
            )
            isolated_chunks.append(chunk_payload)
            if first_guard_result is None:
                first_guard_result = guard_result
        else:
            context_parts.append(chunk.text)

        chunk.metadata.update(metadata)
        if metadata.get("poison_label") == "poisoned" or low_trust:
            poisoned_chunks.append(chunk_payload)
        else:
            safe_chunks.append(chunk_payload)

    if first_guard_result is None:
        joined_context = "\n".join(chunk.text for chunk in chunks)
        first_guard_result = pipeline.check_input(joined_context)

    sanitized_context = "\n".join(context_parts).strip()
    if isolated_chunks:
        sanitized_context = (
            f"{sanitized_context}\n[poisoned retrieved instructions isolated before model context]"
        ).strip()

    return SanitizedRAGContext(
        sanitized_context=sanitized_context,
        safe_chunks=safe_chunks,
        poisoned_chunks=poisoned_chunks,
        isolated_chunks=isolated_chunks,
        guard_result=first_guard_result,
    )


def _is_low_trust(metadata: dict[str, Any]) -> bool:
    trust_level = str(metadata.get("trust_level") or "unknown").lower()
    source_type = str(metadata.get("source_type") or "manual").lower()
    poison_label = str(metadata.get("poison_label") or "unknown").lower()
    return (
        trust_level in _LOW_TRUST_LEVELS
        or source_type in _LOW_TRUST_SOURCES
        or poison_label == "poisoned"
    )
