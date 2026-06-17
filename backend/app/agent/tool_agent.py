from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from app.guardrails.pipeline import GuardMode, GuardrailPipeline
from app.rag.service import InMemoryRAGService
from app.schemas.security import ToolCallVerdict, ToolDecision, ToolManifestEntry, ToolTier
from app.tools.gateway import CallerContext, ToolGateway


class AgentMessage(BaseModel):
    role: str
    content: str


class AgentRunRequest(BaseModel):
    messages: list[AgentMessage]
    caller_role: str = "public"
    guard_mode: GuardMode = GuardMode.ENFORCE
    enable_rag: bool = True
    enable_tools: bool = True
    session_id: str = "agent-demo-session"
    user_id: str = "agent-demo-user"


class AgentToolCall(BaseModel):
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    risk_level: Literal["low", "medium", "high"]


class AgentTraceStep(BaseModel):
    node: str
    blocked: bool = False
    detail: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentRunResponse(BaseModel):
    response: str
    tool_calls: list[AgentToolCall]
    tool_verdicts: list[ToolCallVerdict]
    agent_trace: list[AgentTraceStep]
    blocked: bool


def agent_tool_catalog() -> list[ToolManifestEntry]:
    return [
        ToolManifestEntry(
            name="search_docs",
            description="Search controlled demo documents.",
            tier=ToolTier.PUBLIC,
            parameters={"required": ["query"]},
            danger_patterns=[r"\*:\*", r"\ball\b.*\b(documents?|knowledge\s+base)\b"],
        ),
        ToolManifestEntry(
            name="read_policy",
            description="Read a named policy document.",
            tier=ToolTier.INTERNAL,
            parameters={"required": ["policy_id"]},
            danger_patterns=[r"\*", r"\ball\b"],
        ),
        ToolManifestEntry(
            name="send_report",
            description="Send a prepared report to an approved internal recipient.",
            tier=ToolTier.INTERNAL,
            parameters={"required": ["report_id", "recipient"]},
            danger_patterns=[r"external", r"gmail", r"all"],
        ),
        ToolManifestEntry(
            name="export_data",
            description="Export scoped internal data for administrators.",
            tier=ToolTier.ADMIN,
            parameters={"required": ["scope", "format"]},
            danger_patterns=[r"\ball\b", r"\bfull\b", r"\beverything\b", r"salary"],
        ),
    ]


def run_tool_agent(
    *,
    request: AgentRunRequest,
    rag_service: InMemoryRAGService,
) -> AgentRunResponse:
    user_message = _latest_user_message(request.messages)
    pipeline = GuardrailPipeline(mode=request.guard_mode)
    input_guard = pipeline.check_input(user_message)
    trace = [
        AgentTraceStep(
            node="input_guard",
            blocked=input_guard.action.value == "block",
            detail=input_guard.reason,
            metadata=input_guard.model_dump(mode="json"),
        )
    ]

    retrieval_metadata: dict[str, Any] = {"enabled": request.enable_rag, "chunks_returned": 0}
    if request.enable_rag:
        retrieval = rag_service.query(user_message, caller_role=request.caller_role, limit=3)
        retrieval_metadata = {
            "enabled": True,
            "chunks_returned": retrieval.audit.chunks_returned,
            "action": retrieval.audit.action,
        }
    trace.append(
        AgentTraceStep(
            node="rag_retrieve",
            blocked=False,
            detail="RAG retrieval checked before model planning.",
            metadata=retrieval_metadata,
        )
    )

    tool_call = _plan_tool_call(user_message, enable_tools=request.enable_tools)
    trace.append(
        AgentTraceStep(
            node="model_plan",
            blocked=False,
            detail="Deterministic demo planner selected a candidate tool action.",
            metadata={"tool_call": tool_call.model_dump(mode="json") if tool_call else None},
        )
    )

    verdicts: list[ToolCallVerdict] = []
    tool_blocked = False
    if tool_call is not None:
        verdict = ToolGateway(agent_tool_catalog()).authorize(
            tool_call.tool_name,
            tool_call.arguments,
            CallerContext(
                caller_role=request.caller_role,
                user_id=request.user_id,
                session_id=request.session_id,
            ),
        )
        verdicts.append(verdict)
        tool_blocked = verdict.decision == ToolDecision.BLOCK
    trace.append(
        AgentTraceStep(
            node="tool_authorize",
            blocked=tool_blocked,
            detail="ToolGateway made the final authorization decision.",
            metadata={"verdicts": [verdict.model_dump(mode="json") for verdict in verdicts]},
        )
    )

    tool_result = _mock_tool_result(tool_call, blocked=tool_blocked)
    trace.append(
        AgentTraceStep(
            node="tool_execute_mock",
            blocked=tool_blocked,
            detail=tool_result,
            metadata={"executed": tool_call is not None and not tool_blocked},
        )
    )

    response = "I cannot execute that tool request." if tool_blocked else _agent_response(tool_call)
    output_guard = pipeline.check_output(response)
    output_blocked = output_guard.action.value == "block"
    trace.append(
        AgentTraceStep(
            node="output_guard",
            blocked=output_blocked,
            detail=output_guard.reason,
            metadata=output_guard.model_dump(mode="json"),
        )
    )
    blocked = input_guard.action.value == "block" or tool_blocked or output_blocked
    trace.append(
        AgentTraceStep(
            node="report_trace",
            blocked=blocked,
            detail="Agent trace recorded for report and LangGraph-style visualization.",
            metadata={"nodes": ["input_guard", "rag_retrieve", "model_plan", "tool_authorize", "tool_execute_mock", "output_guard"]},
        )
    )

    return AgentRunResponse(
        response="I cannot comply with that request." if input_guard.action.value == "block" else response,
        tool_calls=[tool_call] if tool_call else [],
        tool_verdicts=verdicts,
        agent_trace=trace,
        blocked=blocked,
    )


def _latest_user_message(messages: list[AgentMessage]) -> str:
    for message in reversed(messages):
        if message.role == "user":
            return message.content
    return messages[-1].content if messages else ""


def _plan_tool_call(prompt: str, *, enable_tools: bool) -> AgentToolCall | None:
    if not enable_tools:
        return None
    text = prompt.lower()
    if "export" in text or "salary" in text or "audit log" in text:
        return AgentToolCall(
            tool_name="export_data",
            arguments={"scope": "audit_logs", "format": "json"},
            risk_level="high",
        )
    if "send" in text and "report" in text:
        return AgentToolCall(
            tool_name="send_report",
            arguments={"report_id": "latest", "recipient": "security-team"},
            risk_level="medium",
        )
    if "policy" in text or "vacation" in text or "read" in text:
        return AgentToolCall(
            tool_name="read_policy",
            arguments={"policy_id": "vacation"},
            risk_level="low",
        )
    if "search" in text or "find" in text:
        return AgentToolCall(
            tool_name="search_docs",
            arguments={"query": prompt, "limit": 3},
            risk_level="low",
        )
    return None


def _mock_tool_result(tool_call: AgentToolCall | None, *, blocked: bool) -> str:
    if tool_call is None:
        return "No tool call proposed."
    if blocked:
        return f"Mock execution skipped for blocked tool {tool_call.tool_name}."
    return f"Mock execution completed for {tool_call.tool_name}."


def _agent_response(tool_call: AgentToolCall | None) -> str:
    if tool_call is None:
        return "No tool was needed for this request."
    return f"Tool {tool_call.tool_name} was authorized in the controlled demo environment."
