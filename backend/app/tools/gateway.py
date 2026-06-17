from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from app.schemas.security import (
    ToolCallVerdict,
    ToolDecision,
    ToolManifestEntry,
    ToolTier,
)


_TIER_RANK = {
    ToolTier.PUBLIC: 0,
    ToolTier.INTERNAL: 1,
    ToolTier.ADMIN: 2,
}


@dataclass(frozen=True)
class CallerContext:
    caller_role: str
    user_id: str
    session_id: str | None = None

    @property
    def tier(self) -> ToolTier:
        if self.caller_role == "admin":
            return ToolTier.ADMIN
        if self.caller_role == "internal":
            return ToolTier.INTERNAL
        return ToolTier.PUBLIC


def default_tool_catalog() -> list[ToolManifestEntry]:
    return [
        ToolManifestEntry(
            name="search_kb",
            description="Search the local knowledge base.",
            tier=ToolTier.PUBLIC,
            parameters={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "maxLength": 500},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 5},
                },
                "required": ["query"],
            },
            danger_patterns=[r"\*:\*", r"\ball\b.*\b(documents?|knowledge\s+base)\b"],
        ),
        ToolManifestEntry(
            name="calculator",
            description="Evaluate safe arithmetic expressions.",
            tier=ToolTier.PUBLIC,
            parameters={
                "type": "object",
                "properties": {"expression": {"type": "string", "maxLength": 120}},
                "required": ["expression"],
            },
            danger_patterns=[r"__import__", r"\beval\s*\(", r"\bexec\s*\(", r"[\\/]\w+"],
        ),
        ToolManifestEntry(
            name="policy_lookup",
            description="Look up internal security policy records.",
            tier=ToolTier.INTERNAL,
            parameters={
                "type": "object",
                "properties": {"policy_id": {"type": "string"}},
                "required": ["policy_id"],
            },
            danger_patterns=[r"\*", r"\ball\b"],
        ),
        ToolManifestEntry(
            name="report_lookup",
            description="Retrieve a specific evaluation report.",
            tier=ToolTier.INTERNAL,
            parameters={
                "type": "object",
                "properties": {"report_id": {"type": "string"}},
                "required": ["report_id"],
            },
            danger_patterns=[r"\ball\b", r"\blist\b.*\breports\b"],
        ),
        ToolManifestEntry(
            name="user_info",
            description="Read current-session user metadata.",
            tier=ToolTier.PUBLIC,
            parameters={
                "type": "object",
                "properties": {"user_id": {"type": "string"}},
                "required": ["user_id"],
            },
            danger_patterns=[],
        ),
        ToolManifestEntry(
            name="export_data",
            description="Export scoped internal data for administrators.",
            tier=ToolTier.ADMIN,
            parameters={
                "type": "object",
                "properties": {
                    "scope": {"type": "string", "enum": ["reports", "audit_logs"]},
                    "format": {"type": "string", "enum": ["json"]},
                },
                "required": ["scope", "format"],
            },
            danger_patterns=[r"\ball\b", r"\bfull\b", r"\beverything\b"],
        ),
    ]


class ToolGateway:
    def __init__(self, catalog: list[ToolManifestEntry]) -> None:
        self._catalog = {entry.name: entry for entry in catalog}

    def authorize(
        self,
        tool_name: str,
        args: dict[str, Any],
        caller_context: CallerContext,
    ) -> ToolCallVerdict:
        manifest = self._catalog.get(tool_name)
        if manifest is None:
            return ToolCallVerdict(
                tool_name=tool_name,
                tier=ToolTier.ADMIN,
                args_passed=args,
                args_check="block",
                permission_check="block",
                decision=ToolDecision.BLOCK,
                reason=f"Unknown tool '{tool_name}' is not registered.",
            )

        args_reason = self._validate_args(manifest, args, caller_context)
        permission_allowed = _TIER_RANK[caller_context.tier] >= _TIER_RANK[manifest.tier]
        if args_reason is not None:
            return ToolCallVerdict(
                tool_name=tool_name,
                tier=manifest.tier,
                args_passed=args,
                args_check="block",
                permission_check="pass" if permission_allowed else "block",
                decision=ToolDecision.BLOCK,
                reason=args_reason,
            )

        if not permission_allowed:
            return ToolCallVerdict(
                tool_name=tool_name,
                tier=manifest.tier,
                args_passed=args,
                args_check="pass",
                permission_check="block",
                decision=ToolDecision.BLOCK,
                reason=(
                    f"Caller tier {caller_context.tier.value} cannot invoke "
                    f"{manifest.tier.value} tool."
                ),
            )

        return ToolCallVerdict(
            tool_name=tool_name,
            tier=manifest.tier,
            args_passed=args,
            args_check="pass",
            permission_check="pass",
            decision=ToolDecision.ALLOW,
            reason="Tool call authorized.",
        )

    def _validate_args(
        self,
        manifest: ToolManifestEntry,
        args: dict[str, Any],
        caller_context: CallerContext,
    ) -> str | None:
        required = manifest.parameters.get("required", [])
        missing = [name for name in required if name not in args]
        if missing:
            return f"Missing required argument(s): {', '.join(missing)}."

        if manifest.name == "user_info" and args.get("user_id") != caller_context.user_id:
            return "user_info may only query the current session user."

        combined_args = " ".join(str(value) for value in args.values())
        for pattern in manifest.danger_patterns:
            if re.search(pattern, combined_args, re.I):
                return f"Blocked dangerous argument pattern: {pattern}."

        if manifest.name == "search_kb" and int(args.get("limit", 1)) > 5:
            return "Argument 'limit' exceeds maximum allowed value 5."

        if manifest.name == "calculator":
            expression = str(args.get("expression", ""))
            if re.search(r"[^0-9+\-*/().\s]", expression):
                return "Calculator expression contains non-arithmetic characters."

        return None
