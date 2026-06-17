from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field


FailureSource = Literal["security_cycle", "garak", "rag", "tool_agent"]


class FailureIngestRequest(BaseModel):
    source: FailureSource = "security_cycle"
    model: str | None = None
    guard_mode: str | None = None
    original_run_id: str | None = None
    failures: list[dict[str, Any]] = Field(default_factory=list)


class FailureIngestResponse(BaseModel):
    run_id: str
    total_ingested: int
    regression_payloads: list[dict[str, Any]]
    files: dict[str, str] = Field(default_factory=dict)


def ingest_failures(*, request: FailureIngestRequest, reports_dir: str | Path) -> FailureIngestResponse:
    payloads = [
        _normalize_failure(failure, request=request, index=index)
        for index, failure in enumerate(request.failures)
    ]
    payloads = [payload for payload in payloads if payload["payload"]]
    run_id = f"failure-ingest-{uuid4().hex[:8]}"
    output_dir = Path(reports_dir) / run_id
    output_dir.mkdir(parents=True, exist_ok=True)
    payloads_path = output_dir / "failure-ingest-payloads.json"
    manifest_path = output_dir / "failure-ingest-manifest.json"
    payloads_path.write_text(
        json.dumps(payloads, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    manifest = {
        "run_id": run_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source": request.source,
        "model": request.model,
        "guard_mode": request.guard_mode,
        "original_run_id": request.original_run_id,
        "total_ingested": len(payloads),
    }
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return FailureIngestResponse(
        run_id=run_id,
        total_ingested=len(payloads),
        regression_payloads=payloads,
        files={
            "next_payloads": str(payloads_path),
            "manifest": str(manifest_path),
        },
    )


def _normalize_failure(
    failure: dict[str, Any],
    *,
    request: FailureIngestRequest,
    index: int,
) -> dict[str, Any]:
    source = str(failure.get("source") or request.source)
    model = failure.get("model") or request.model
    guard_mode = failure.get("guard_mode") or request.guard_mode
    original_run_id = failure.get("original_run_id") or request.original_run_id
    prompt = str(failure.get("prompt") or failure.get("payload") or "").strip()
    response = str(failure.get("response") or "").strip()
    probe = str(failure.get("probe") or _default_probe(source, index))
    failure_type = str(
        failure.get("failure_type")
        or _classify_failure(source=source, probe=probe, prompt=prompt, response=response)
    )
    return {
        "source": source,
        "model": model,
        "guard_mode": guard_mode,
        "original_run_id": original_run_id,
        "probe": probe,
        "failure_type": failure_type,
        "payload": prompt,
        "response_excerpt": response[:500],
        "expected_guard": "block",
        "metadata": {
            "ingest_index": index,
            "normalizer": "failure_ingest_v1",
        },
    }


def _classify_failure(*, source: str, probe: str, prompt: str, response: str) -> str:
    text = f"{source} {probe} {prompt} {response}".lower()
    if "promptinject.hijackhatehumans" in text or "i hate humans" in text:
        return "garak_promptinject_hijack"
    if "coverage_expansion" in text or (
        "paraphrase" in text and "multi-turn" in text and ("translated" in text or "translation" in text)
    ):
        return "attack_coverage"
    if "tool" in text or "export_data" in text:
        return "tool_abuse"
    if "rag" in text or "retrieved" in text or "poison" in text:
        return "rag_poisoning"
    return "direct_injection"


def _default_probe(source: str, index: int) -> str:
    if source == "garak":
        return "garak_failure"
    return f"failure_payload_{index + 1}"
