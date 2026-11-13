#!/usr/bin/env python3
"""导出 ASGP 领域契约的 JSON Schema 到 contracts/。

契约以 Pydantic 模型为唯一事实来源；JSON Schema 是给外部集成和前端
使用的固定视图。修改契约后必须重新生成本目录并提交。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from domain import (  # noqa: E402
    AgentProductDescriptor,
    Asset,
    AssetInstance,
    AssetRelease,
    Publisher,
    DetectorDescriptor,
    DetectorRun,
    EvidenceRef,
    Execution,
    Finding,
    HookEventCapability,
    Intent,
    ModelProviderProfile,
    ProcessInfo,
    ResourceInfo,
    RuntimeEvent,
)
from domain.timeline import TimelineEntry, TimelineResponse
from domain.attribution import EventAttribution
from domain.effect_diff import EffectDiffItem, ExecutionEffectDiff
from domain.approval import ApprovalRequest
from domain.governance import Admission,Incident,IncidentEvidence,PolicyDecision,PolicyRuleSet,RiskAssessment

SCHEMAS = {
    "effect-diff-item": EffectDiffItem,
    "execution-effect-diff": ExecutionEffectDiff,
    "event-attribution": EventAttribution,
    "approval-request": ApprovalRequest,
    "admission": Admission,
    "incident": Incident,
    "incident-evidence": IncidentEvidence,
    "policy-decision": PolicyDecision,
    "policy-version": PolicyRuleSet,
    "risk-assessment": RiskAssessment,
    "timeline-entry": TimelineEntry,
    "timeline-response": TimelineResponse,
    "agent-product-descriptor": AgentProductDescriptor,
    "asset": Asset,
    "asset-instance": AssetInstance,
    "asset-release": AssetRelease,
    "publisher": Publisher,
    "detector-descriptor": DetectorDescriptor,
    "detector-run": DetectorRun,
    "evidence-ref": EvidenceRef,
    "execution": Execution,
    "finding": Finding,
    "hook-event-capability": HookEventCapability,
    "intent": Intent,
    "model-provider-profile": ModelProviderProfile,
    "process-info": ProcessInfo,
    "resource-info": ResourceInfo,
    "runtime-event": RuntimeEvent,
}


def main() -> int:
    out_dir = ROOT / "contracts"
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, model in SCHEMAS.items():
        schema = model.model_json_schema(ref_template="#/$defs/{model}")
        target = out_dir / f"{name}.schema.json"
        target.write_text(
            json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"已导出 {target.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
