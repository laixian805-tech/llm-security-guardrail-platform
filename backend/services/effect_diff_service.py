"""指令来源谱系 × 预期/真实 OS 副作用差分服务。

核心问题：传统规则只看单条工具调用或静态文本；ASGP 把模型层的 Intent
（含来源谱系与参数预期边界）与 AttributionService 归因到的 Linux Audit
真实系统事件逐条做集合差分，识别“名称看似正常、实则越出预期边界”的
隐式 OS 副作用，并诚实披露未归因事件数（绝不硬连）。
"""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from domain import (
    AttributionMethod,
    Confidence,
    EffectDiffItem,
    EffectDiffVerdict,
    ExecutionEffectDiff,
    SourceKind,
)
from services.evidence_rules import (
    is_external_host,
    is_lots_endpoint,
    is_sensitive_path,
    normalize_hint_path,
)
from services.ingestion_service import IngestError

EFFECT_DIFF_VERSION = "effect-diff-v1"

TRUST_TIERS = {
    SourceKind.USER_TASK.value: "high",
    SourceKind.WORKSPACE_CONFIG.value: "medium",
    SourceKind.INSTALLED_SKILL.value: "low",
    SourceKind.MCP_SERVER.value: "low",
    SourceKind.TOOL_OUTPUT.value: "untrusted",
    SourceKind.UNKNOWN.value: "unknown",
}

READ_TOOLS = frozenset({
    "read", "read_file", "view_file", "cat", "glob", "grep",
    "grep_search", "find_by_name", "ls", "list_dir",
})
WRITE_TOOLS = frozenset({
    "write", "write_file", "edit", "edit_file", "replace_file_content",
    "multi_replace_file_content", "create_file",
})
NET_TOOLS = frozenset({"webfetch", "web_fetch", "fetch", "http_request", "search_web"})
EXEC_TOOLS = frozenset({"bash", "run_command", "shell", "execute_command", "terminal", "run_shell_command"})


def _tool_category(tool_name: str) -> str:
    lowered = tool_name.strip().lower()
    if lowered in READ_TOOLS:
        return "read"
    if lowered in WRITE_TOOLS:
        return "write"
    if lowered in NET_TOOLS:
        return "network"
    if lowered in EXEC_TOOLS:
        return "exec"
    return "other"


def _resource_hints(intent: dict[str, Any]) -> list[str]:
    try:
        summary = json.loads(intent.get("params_summary") or "")
    except (ValueError, TypeError):
        return []
    if not isinstance(summary, dict):
        return []
    hints = summary.get("resource_hints")
    if not hints and summary.get("resource_hint"):
        hints = [summary["resource_hint"]]
    if not isinstance(hints, list):
        return []
    return [str(h) for h in hints if h]


def _expected_scope(category: str, hints: list[str]) -> str:
    if category == "read":
        return f"仅限只读文件：{', '.join(hints)}" if hints else "仅限非敏感文件读取，禁止网络外连"
    if category == "write":
        return f"仅限写入目标：{', '.join(hints)}" if hints else "仅限非敏感文件写入，禁止网络外连"
    if category == "network":
        return f"仅限网络访问：{', '.join(hints)}" if hints else "仅限预期网络请求，禁止访问本地敏感文件"
    if category == "exec":
        return f"命令声明目标：{', '.join(hints)}（禁止越权读敏感凭据或外连未登记外部地址）" if hints else "命令行执行（禁止越权读敏感凭据或外连未登记外部地址）"
    return f"声明目标：{', '.join(hints)}" if hints else "未声明具体资源作用域"


def _target_matches_hints(target: str, hints: list[str]) -> bool:
    norm = normalize_hint_path(target) or target
    for hint in hints:
        if norm == hint or norm.startswith(hint.rstrip("/") + "/"):
            return True
    return False


def _evaluate_event(
    *,
    category: str,
    hints: list[str],
    source_kind: str,
    event: dict[str, Any],
) -> tuple[EffectDiffVerdict, str]:
    etype = event.get("event_type") or ""
    path = event.get("resource_path")
    host = event.get("resource_host")
    low_trust = source_kind in (
        SourceKind.INSTALLED_SKILL.value,
        SourceKind.MCP_SERVER.value,
        SourceKind.TOOL_OUTPUT.value,
    )

    if etype == "network_connect":
        if not host:
            return (
                EffectDiffVerdict.UNVERIFIED,
                "无远端主机地址的本地/未解析套接字连接，不作为外部网络越界",
            )
        if category in ("read", "write"):
            return (
                EffectDiffVerdict.UNDECLARED_SIDE_EFFECT,
                f"模型调用属于 {category} 工具，预期无网络活动，但 OS 观测到外连 {host}",
            )
        if is_lots_endpoint(host) and not (hints and host and _target_matches_hints(host, hints)):
            prefix = f"低信任来源({source_kind})诱导的" if low_trust else ""
            return (
                EffectDiffVerdict.UNDECLARED_SIDE_EFFECT,
                f"{prefix}LOTS 临时外带/隧道端点外连：{host}",
            )
        if is_external_host(host) and not (hints and host and _target_matches_hints(host, hints)):
            prefix = f"低信任来源({source_kind})诱导的" if low_trust else ""
            return (
                EffectDiffVerdict.UNDECLARED_SIDE_EFFECT,
                f"{prefix}未声明外部网络外连：{host}",
            )
        return (EffectDiffVerdict.WITHIN_EXPECTED, "网络连接在可信端点或声明目标范围内")

    if etype == "file_access":
        if is_sensitive_path(path):
            explicitly_expected = bool(hints and path and _target_matches_hints(path, hints))
            if low_trust or not explicitly_expected:
                prefix = f"低信任来源({source_kind})诱导下" if low_trust else ""
                return (
                    EffectDiffVerdict.UNDECLARED_SIDE_EFFECT,
                    f"{prefix}出现未预期敏感路径访问：{path}",
                )
        if category in ("read", "write") and hints and path and not _target_matches_hints(path, hints):
            return (
                EffectDiffVerdict.UNDECLARED_SIDE_EFFECT,
                f"文件访问超出参数声明路径（声明 {hints}，实测 {path}）",
            )
        return (EffectDiffVerdict.WITHIN_EXPECTED, "文件访问符合预期边界")

    if etype in ("process_start", "process_exec"):
        if category in ("read", "write"):
            return (
                EffectDiffVerdict.UNDECLARED_SIDE_EFFECT,
                f"{category} 工具不应派生新执行进程（实测 {event.get('executable') or path or 'exec'}）",
            )
        return (EffectDiffVerdict.WITHIN_EXPECTED, "进程派生符合命令执行语义")

    return (EffectDiffVerdict.UNVERIFIED, f"未覆盖的事件类型：{etype}")


class EffectDiffService:
    """基于归因证据计算每次执行的来源谱系与 OS 副作用差分。"""

    def __init__(self, storage) -> None:
        self.storage = storage

    def analyze(self, execution_id: str) -> dict[str, Any]:
        with self.storage.connection() as conn:
            execution = conn.execute(
                "SELECT * FROM executions WHERE execution_id = ?", (execution_id,)
            ).fetchone()
            if not execution:
                raise IngestError("unknown_execution", 404)
            intents = [
                dict(row)
                for row in conn.execute(
                    "SELECT * FROM intents WHERE execution_id = ? ORDER BY occurred_at, intent_id",
                    (execution_id,),
                ).fetchall()
            ]
            intent_ids = [row["intent_id"] for row in intents]
            edges: list[dict[str, Any]] = []
            events_by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
            if intent_ids:
                marks = ",".join("?" * len(intent_ids))
                edges = [
                    dict(row)
                    for row in conn.execute(
                        "SELECT * FROM event_attributions"
                        f" WHERE intent_id IN ({marks}) ORDER BY score DESC, event_id",
                        intent_ids,
                    ).fetchall()
                ]
                event_ids = sorted({row["event_id"] for row in edges})
                if event_ids:
                    ev_marks = ",".join("?" * len(event_ids))
                    for row in conn.execute(
                        "SELECT * FROM runtime_events"
                        f" WHERE host_id = ? AND device_id = ? AND event_id IN ({ev_marks})",
                        [execution["host_id"], execution["device_id"], *event_ids],
                    ).fetchall():
                        r = dict(row)
                        events_by_key[(r["host_id"], r["collector_id"], r["event_id"])] = r

            window_total = conn.execute(
                "SELECT COUNT(*) FROM runtime_events"
                " WHERE host_id = ? AND device_id = ? AND occurred_at >= ?"
                " AND event_type != 'hook_anchor'",
                (execution["host_id"], execution["device_id"], execution["started_at"]),
            ).fetchone()[0]

        edges_by_intent: dict[str, list[dict[str, Any]]] = {}
        attributed_event_keys: set[tuple[str, str, str]] = set()
        for edge in edges:
            key = (edge["host_id"], edge["collector_id"], edge["event_id"])
            if edge["selected"]:
                attributed_event_keys.add(key)
            edges_by_intent.setdefault(edge["intent_id"], []).append(edge)

        # 若一条事件没有 selected 边，也保留候选边做可见性标记，但优先用 selected 边。
        if not attributed_event_keys:
            for edge in edges:
                attributed_event_keys.add((edge["host_id"], edge["collector_id"], edge["event_id"]))

        items: list[EffectDiffItem] = []
        source_counter: Counter[str] = Counter()
        undeclared = 0
        within_expected = 0

        for intent in intents:
            raw_kind = intent.get("source_kind") or SourceKind.UNKNOWN.value
            try:
                source_kind = SourceKind(raw_kind)
            except ValueError:
                source_kind = SourceKind.UNKNOWN
            source_counter[source_kind.value] += 1
            source_ref = intent.get("source_ref")
            trust_tier = TRUST_TIERS[source_kind.value]
            category = _tool_category(intent["tool_name"])
            hints = _resource_hints(intent)
            scope = _expected_scope(category, hints)

            intent_edges = edges_by_intent.get(intent["intent_id"], [])
            selected_edges = [e for e in intent_edges if e["selected"]]
            chosen = selected_edges or intent_edges[:1]

            if not chosen:
                items.append(
                    EffectDiffItem(
                        intent_id=intent["intent_id"],
                        tool_name=intent["tool_name"],
                        source_kind=source_kind,
                        source_ref=source_ref,
                        trust_tier=trust_tier,
                        expected_scope=scope,
                        verdict=EffectDiffVerdict.NO_OBSERVED_EFFECT,
                        reason=(
                            "该工具调用已被策略拒绝（decision=deny），未观测到对应 OS 副作用"
                            if intent.get("decision") == "deny"
                            else "未归因到对应的 OS 级系统事件（保持留空，不做猜测）"
                        ),
                    )
                )
                continue

            for edge in chosen:
                ev = events_by_key.get((edge["host_id"], edge["collector_id"], edge["event_id"]))
                if not ev or ev.get("event_type") == "hook_anchor":
                    continue
                verdict, reason = _evaluate_event(
                    category=category,
                    hints=hints,
                    source_kind=source_kind.value,
                    event=ev,
                )
                if verdict is EffectDiffVerdict.UNDECLARED_SIDE_EFFECT:
                    undeclared += 1
                elif verdict is EffectDiffVerdict.WITHIN_EXPECTED:
                    within_expected += 1
                observed = ev.get("resource_path") or (
                    f"{ev.get('resource_host')}:{ev.get('resource_port')}"
                    if ev.get("resource_host") and ev.get("resource_port")
                    else ev.get("resource_host") or ev.get("executable") or ev.get("event_type")
                )
                items.append(
                    EffectDiffItem(
                        intent_id=intent["intent_id"],
                        tool_name=intent["tool_name"],
                        source_kind=source_kind,
                        source_ref=source_ref,
                        trust_tier=trust_tier,
                        expected_scope=scope,
                        event_id=ev["event_id"],
                        event_type=ev["event_type"],
                        observed_target=observed,
                        attribution_method=AttributionMethod(edge["method"]),
                        attribution_confidence=Confidence(edge["confidence"]),
                        verdict=verdict,
                        reason=reason,
                    )
                )

        result = ExecutionEffectDiff(
            execution_id=execution_id,
            rule_version=EFFECT_DIFF_VERSION,
            intent_count=len(intents),
            attributed_event_count=len(attributed_event_keys),
            unattributed_event_count=max(window_total - len(attributed_event_keys), 0),
            undeclared_count=undeclared,
            within_expected_count=within_expected,
            by_source_kind=dict(source_counter),
            items=items,
        )
        return result.model_dump(mode="json")
