from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError, field_validator


GuardPackStage = Literal["pre_input", "post_output"]


class GuardPackRule(BaseModel):
    rule_name: str = Field(min_length=1, max_length=100)
    stage: GuardPackStage = "pre_input"
    pattern: str = Field(min_length=1, max_length=800)
    reason: str = Field(min_length=1, max_length=300)
    confidence: float = Field(default=0.9, ge=0.0, le=1.0)
    source_failure_type: str | None = None
    enabled: bool = True

    @field_validator("rule_name")
    @classmethod
    def validate_rule_name(cls, value: str) -> str:
        if not re.fullmatch(r"[a-zA-Z0-9_.:-]+", value):
            raise ValueError("rule_name may only contain letters, digits, underscore, dash, dot, or colon")
        return value

    @field_validator("pattern")
    @classmethod
    def validate_pattern(cls, value: str) -> str:
        try:
            re.compile(value, re.I)
        except re.error as caught:
            raise ValueError(f"invalid regex pattern: {caught}") from caught
        return value


class GuardPack(BaseModel):
    schema_version: int = 1
    source_run_id: str | None = None
    source_guard_pack: str | None = None
    guard_profile: str | None = None
    target_surface: str | None = None
    active: bool = True
    rules: list[GuardPackRule] = Field(default_factory=list)
    semantic_expansions: list[str] = Field(default_factory=list)
    isolation_sources: list[str] = Field(default_factory=list)
    next_round_payloads: list[dict[str, Any]] = Field(default_factory=list)


class GuardPackValidationResult(BaseModel):
    valid: bool
    errors: list[str] = Field(default_factory=list)
    guard_pack: GuardPack


def active_guard_pack_path(assets_root: str) -> Path:
    return Path(assets_root) / "guard-packs" / "active.json"


def normalize_guard_pack(payload: dict[str, Any] | None) -> GuardPackValidationResult:
    raw = dict(payload or {})
    errors: list[str] = []
    raw_rules = list(raw.get("rules") or [])
    raw_rules.extend(raw.get("rule_templates") or [])

    rules: list[GuardPackRule] = []
    for index, raw_rule in enumerate(raw_rules):
        if not isinstance(raw_rule, dict):
            errors.append(f"rule[{index}] must be an object")
            continue
        try:
            rules.append(
                GuardPackRule.model_validate(
                    {
                        "rule_name": raw_rule.get("rule_name"),
                        "stage": raw_rule.get("stage", "pre_input"),
                        "pattern": raw_rule.get("pattern"),
                        "reason": raw_rule.get("reason") or raw_rule.get("description") or "Dynamic guard pack rule matched.",
                        "confidence": raw_rule.get("confidence", 0.9),
                        "source_failure_type": raw_rule.get("source_failure_type"),
                        "enabled": raw_rule.get("enabled", True),
                    }
                )
            )
        except ValidationError as caught:
            errors.append(f"rule[{index}] invalid: {caught.errors()[0]['msg']}")

    guard_pack = GuardPack(
        schema_version=int(raw.get("schema_version") or 1),
        source_run_id=raw.get("source_run_id"),
        source_guard_pack=raw.get("source_guard_pack"),
        guard_profile=raw.get("guard_profile"),
        target_surface=raw.get("target_surface"),
        active=bool(raw.get("active", True)),
        rules=rules,
        semantic_expansions=[
            str(item) for item in raw.get("semantic_expansions", []) if str(item).strip()
        ],
        isolation_sources=[
            str(item) for item in raw.get("isolation_sources", []) if str(item).strip()
        ],
        next_round_payloads=[
            item for item in raw.get("next_round_payloads", []) if isinstance(item, dict)
        ],
    )
    if not rules:
        errors.append("guard pack must contain at least one valid rule")
    return GuardPackValidationResult(valid=not errors, errors=errors, guard_pack=guard_pack)


def runtime_rules_from_pack(guard_pack: GuardPack | None) -> list[dict[str, Any]]:
    if guard_pack is None or not guard_pack.active:
        return []
    return [
        rule.model_dump(mode="json")
        for rule in guard_pack.rules
        if rule.enabled
    ]


def read_active_guard_pack(path: str | Path) -> GuardPack | None:
    pack_path = Path(path)
    if not pack_path.exists():
        return None
    try:
        payload = json.loads(pack_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    validation = normalize_guard_pack(payload if isinstance(payload, dict) else {})
    if not validation.valid:
        return None
    return validation.guard_pack


def write_active_guard_pack(path: str | Path, guard_pack: GuardPack) -> None:
    pack_path = Path(path)
    pack_path.parent.mkdir(parents=True, exist_ok=True)
    pack_path.write_text(
        json.dumps(guard_pack.model_dump(mode="json"), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def delete_active_guard_pack(path: str | Path) -> bool:
    pack_path = Path(path)
    if not pack_path.exists():
        return False
    pack_path.unlink()
    return True
