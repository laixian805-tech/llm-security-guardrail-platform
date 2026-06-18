from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class RegressionSetCreateRequest(BaseModel):
    name: str = "default"
    source: str = "manual"
    original_run_id: str | None = None
    payloads: list[dict[str, Any]] = Field(default_factory=list)


class RegressionSetSummary(BaseModel):
    set_id: str
    name: str
    version: int
    source: str
    original_run_id: str | None = None
    total_payloads: int
    created_at: str
    files: dict[str, str] = Field(default_factory=dict)


class RegressionSetResponse(RegressionSetSummary):
    payloads: list[dict[str, Any]] = Field(default_factory=list)


class RegressionSetListResponse(BaseModel):
    regression_sets: list[RegressionSetSummary]


def create_regression_set(*, request: RegressionSetCreateRequest, reports_dir: str | Path) -> RegressionSetResponse:
    root = _regression_root(reports_dir)
    root.mkdir(parents=True, exist_ok=True)
    name = _safe_name(request.name)
    version = _next_version(root, name)
    set_id = f"{name}-v{version}"
    output_dir = root / set_id
    output_dir.mkdir(parents=True, exist_ok=True)
    created_at = datetime.now(timezone.utc).isoformat()
    payloads = [_normalize_payload(payload, index=index) for index, payload in enumerate(request.payloads)]
    payloads = [payload for payload in payloads if payload["payload"]]
    payloads_path = output_dir / "regression-payloads.json"
    manifest_path = output_dir / "regression-set.json"
    manifest = {
        "set_id": set_id,
        "name": name,
        "version": version,
        "source": request.source,
        "original_run_id": request.original_run_id,
        "total_payloads": len(payloads),
        "created_at": created_at,
        "files": {
            "payloads": str(payloads_path),
            "manifest": str(manifest_path),
        },
    }
    payloads_path.write_text(json.dumps(payloads, ensure_ascii=False, indent=2), encoding="utf-8")
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return RegressionSetResponse(**manifest, payloads=payloads)


def list_regression_sets(*, reports_dir: str | Path) -> RegressionSetListResponse:
    root = _regression_root(reports_dir)
    summaries = []
    for manifest_path in root.glob("*/regression-set.json") if root.exists() else []:
        try:
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        summaries.append(RegressionSetSummary.model_validate(payload))
    summaries.sort(key=lambda item: (item.created_at, item.set_id), reverse=True)
    return RegressionSetListResponse(regression_sets=summaries)


def load_regression_set(*, reports_dir: str | Path, set_id: str) -> RegressionSetResponse:
    root = _regression_root(reports_dir).resolve()
    set_dir = (root / set_id).resolve()
    if not str(set_dir).startswith(str(root) + "/"):
        raise FileNotFoundError(set_id)
    manifest_path = set_dir / "regression-set.json"
    payloads_path = set_dir / "regression-payloads.json"
    if not manifest_path.exists() or not payloads_path.exists():
        raise FileNotFoundError(set_id)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    payloads = json.loads(payloads_path.read_text(encoding="utf-8"))
    return RegressionSetResponse(**manifest, payloads=payloads if isinstance(payloads, list) else [])


def _regression_root(reports_dir: str | Path) -> Path:
    return Path(reports_dir) / "regression-sets"


def _safe_name(name: str) -> str:
    cleaned = "".join(char if char.isalnum() or char in {"-", "_"} else "-" for char in name.strip().lower())
    return cleaned.strip("-") or "default"


def _next_version(root: Path, name: str) -> int:
    versions = []
    for path in root.glob(f"{name}-v*/regression-set.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            versions.append(int(payload.get("version") or 0))
        except (OSError, json.JSONDecodeError, ValueError):
            continue
    return max(versions or [0]) + 1


def _normalize_payload(payload: dict[str, Any], *, index: int) -> dict[str, Any]:
    text = str(payload.get("payload") or payload.get("prompt") or "").strip()
    return {
        "probe": str(payload.get("probe") or payload.get("failure_type") or f"regression_{index + 1}"),
        "failure_type": payload.get("failure_type"),
        "payload": text,
        "expected_guard": payload.get("expected_guard", "block"),
        "source": payload.get("source"),
        "metadata": {
            **dict(payload.get("metadata") or {}),
            "regression_index": index,
        },
    }
