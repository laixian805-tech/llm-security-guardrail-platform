"""扫描器输出归一化。

统一模型只做映射，不丢弃上游报告、规则 ID、版本和置信度。severity 与
confidence 分开：上游只给一个等级时填 severity，confidence 保持 unknown，
不由分数反推。
"""

from __future__ import annotations

import hashlib
from typing import Any

from domain import Confidence, EvidenceRef, Severity
from adapters.detectors.base import NormalizedFinding

_CRITICAL = {"critical", "error", "fatal", "blocker"}
_HIGH = {"high", "warning", "major"}
_MEDIUM = {"medium", "moderate"}
_LOW = {"low", "note", "minor"}
_INFO = {"info", "informational"}


def map_severity(value: Any) -> Severity:
    normalized = str(value or "").strip().lower()
    if normalized in _CRITICAL:
        return Severity.CRITICAL
    if normalized in _HIGH:
        return Severity.HIGH
    if normalized in _MEDIUM:
        return Severity.MEDIUM
    if normalized in _LOW:
        return Severity.LOW
    if normalized in _INFO:
        return Severity.INFO
    return Severity.UNKNOWN


def make_fingerprint(detector_id: str, rule_id: str, location: str, excerpt: str) -> str:
    """跨扫描去重的稳定指纹：detector + rule + 归一化位置 + 证据片段。"""
    material = "".join([detector_id, rule_id, location.strip().lower(), excerpt.strip()[:400]])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def _as_float(value: Any) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def sarif_findings(report: Any) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    if not isinstance(report, dict):
        return findings
    runs = report.get("runs") if isinstance(report.get("runs"), list) else []
    for run in runs:
        if not isinstance(run, dict):
            continue
        driver = run.get("tool", {}).get("driver", {}) if isinstance(run.get("tool"), dict) else {}
        if not isinstance(driver, dict):
            driver = {}
        rules = {
            str(item.get("id")): item
            for item in (driver.get("rules") or [])
            if isinstance(item, dict) and item.get("id")
        }
        results = run.get("results") if isinstance(run.get("results"), list) else []
        for result in results:
            if not isinstance(result, dict):
                continue
            rule_id = str(result.get("ruleId") or "unknown")
            rule = rules.get(rule_id, {})
            message = result.get("message") or {}
            text = str(message.get("text") or message.get("markdown") or rule_id) if isinstance(message, dict) else rule_id
            locations = result.get("locations") or []
            physical = {}
            if locations and isinstance(locations[0], dict):
                physical = locations[0].get("physicalLocation") or {}
            if not isinstance(physical, dict):
                physical = {}
            artifact = physical.get("artifactLocation") or {}
            region = physical.get("region") or {}
            artifact = artifact if isinstance(artifact, dict) else {}
            region = region if isinstance(region, dict) else {}
            uri = str(artifact.get("uri") or "")
            line = _as_int(region.get("startLine"))
            properties = result.get("properties") if isinstance(result.get("properties"), dict) else {}
            rule_properties = rule.get("properties") if isinstance(rule.get("properties"), dict) else {}
            raw_score = properties.get("security-severity") or properties.get("risk_score") or rule_properties.get("security-severity")
            title_value = rule.get("shortDescription") if isinstance(rule.get("shortDescription"), dict) else {}
            default_level = (rule.get("defaultConfiguration") or {}).get("level") if isinstance(rule.get("defaultConfiguration"), dict) else None
            findings.append(NormalizedFinding(
                rule_id=rule_id,
                upstream_rule_id=rule_id,
                title=str(title_value.get("text") or rule.get("name") or rule_id),
                severity=map_severity(result.get("level") or default_level),
                message=text,
                upstream_risk_score=_as_float(raw_score),
                evidence_refs=_evidence_refs("sarif_location", uri, line),
                fingerprint=str((result.get("partialFingerprints") or {}).get("primaryLocationLineHash") or "")
                or make_fingerprint("sarif", rule_id, uri, text),
                metadata=dict(properties),
            ))
    return findings


def _rows_from(report: dict[str, Any]) -> list[Any]:
    rows: list[Any] = []
    for key in ("findings", "issues", "vulnerabilities", "alerts", "results", "risks", "scan_results"):
        value = report.get(key)
        if isinstance(value, list):
            rows.extend(value)
    return rows


def _location_of(item: dict[str, Any]) -> tuple[str, int]:
    location = item.get("location") or item.get("locations") or {}
    if isinstance(location, list):
        location = location[0] if location else {}
    if not isinstance(location, dict):
        location = {}
    path = str(item.get("file") or item.get("path") or location.get("file") or location.get("path") or "")
    line = _as_int(item.get("line") or location.get("line"))
    return path, line


def _evidence_refs(kind: str, path: str, line: int) -> tuple[EvidenceRef, ...]:
    # 上游没给位置时不造证据；空 uri 比没有证据更糟。
    if not path:
        return ()
    return (EvidenceRef(kind=kind, uri=f"{path}:{line}" if line else path, label=path),)


def generic_json_findings(report: Any) -> list[NormalizedFinding]:
    if isinstance(report, list):
        report = {"findings": report}
    if not isinstance(report, dict):
        return []

    findings: list[NormalizedFinding] = []
    for item in _rows_from(report):
        if not isinstance(item, dict):
            continue

        analyzer_findings = item.get("findings")
        if isinstance(analyzer_findings, dict):
            entity_name = str(item.get("tool_name") or item.get("prompt_name") or
                              item.get("resource_name") or item.get("server_name") or "")
            for analyzer, details in analyzer_findings.items():
                if not isinstance(details, dict) or not int(details.get("total_findings") or 0):
                    continue
                names = details.get("threat_names") or []
                summary = str(details.get("threat_summary") or ", ".join(map(str, names)))
                findings.append(NormalizedFinding(
                    rule_id=str(analyzer),
                    upstream_rule_id=str(analyzer),
                    title=str(details.get("threat_summary") or analyzer),
                    severity=map_severity(details.get("severity")),
                    message=summary,
                    evidence_refs=_evidence_refs("analyzer_entity", entity_name, 0),
                    fingerprint=make_fingerprint("analyzer", str(analyzer), entity_name, summary),
                    metadata={"analyzer": analyzer, "total_findings": details.get("total_findings"),
                              "threat_names": names},
                ))
            continue

        path, line = _location_of(item)
        raw_score = item.get("risk_score", item.get("riskScore", item.get("score")))
        rule_id = str(item.get("ruleId") or item.get("rule_id") or item.get("code") or item.get("id") or "unknown")
        title = str(item.get("title") or item.get("name") or item.get("risk") or item.get("rule") or "发现项")
        message = str(item.get("message") or item.get("description") or item.get("detail") or "")
        metadata = item.get("metadata") or item.get("details") or {}
        findings.append(NormalizedFinding(
            rule_id=rule_id,
            upstream_rule_id=rule_id,
            title=title,
            severity=map_severity(item.get("severity") or item.get("level") or item.get("risk_level")),
            message=message,
            upstream_risk_score=_as_float(raw_score),
            evidence_refs=_evidence_refs("file_location", path, line),
            fingerprint=str(item.get("fingerprint") or item.get("id") or "")
            or make_fingerprint("json", rule_id, path, message),
            metadata=metadata if isinstance(metadata, dict) else {"value": metadata},
        ))
    return findings


def snyk_findings(report: Any) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    if not isinstance(report, dict):
        return findings
    for path_result in report.get("scan_path_responses", []) or []:
        if not isinstance(path_result, dict):
            continue
        path = str(path_result.get("path") or "")
        for entity_type, collection_key in (("skill", "skill_risks"), ("server", "server_risks")):
            for entity in path_result.get(collection_key, []) or []:
                if not isinstance(entity, dict):
                    continue
                for risk_id, value in (entity.get("risk_indexes") or {}).items():
                    if not isinstance(value, dict):
                        continue
                    score = value.get("score")
                    evidence = str(value.get("evidence") or "")
                    if score in (None, 0) and not evidence:
                        continue
                    locations = value.get("locations") or []
                    occurrence = {}
                    if locations and isinstance(locations[0], dict):
                        occurrence = locations[0].get("start") or {}
                    if not isinstance(occurrence, dict):
                        occurrence = {}
                    file_path = str(occurrence.get("path") or path)
                    line = _as_int(occurrence.get("line"))
                    findings.append(NormalizedFinding(
                        rule_id=str(risk_id),
                        upstream_rule_id=str(risk_id),
                        title=str(risk_id).replace("_", " ").title(),
                        # Snyk 只给分数不给等级，severity 保持 unknown。
                        severity=Severity.UNKNOWN,
                        message=evidence,
                        upstream_risk_score=_as_float(score),
                        evidence_refs=_evidence_refs("file_location", file_path, line),
                        fingerprint=make_fingerprint("snyk", str(risk_id), file_path, evidence),
                        metadata={"entity_type": entity_type, "entity": entity.get("name", "")},
                    ))
    return findings


def is_sarif(report: Any) -> bool:
    return isinstance(report, dict) and report.get("version") == "2.1.0" and isinstance(report.get("runs"), list)


def normalize_report(report: Any) -> list[NormalizedFinding]:
    if is_sarif(report):
        return sarif_findings(report)
    if isinstance(report, dict) and isinstance(report.get("scan_path_responses"), list):
        return snyk_findings(report)
    return generic_json_findings(report)
