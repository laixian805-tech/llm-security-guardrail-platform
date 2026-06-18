from __future__ import annotations

import importlib.util
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


GraphCallable = Callable[[dict[str, Any]], dict[str, Any]]
GraphNode = tuple[str, GraphCallable]


@dataclass(frozen=True)
class GraphNodeSpec:
    name: str
    func: GraphCallable
    public_name: str | None = None
    blocked_state_key: str | None = None


class GraphExecutionError(RuntimeError):
    def __init__(self, message: str, *, state: dict[str, Any], original: Exception) -> None:
        super().__init__(message)
        self.state = state
        self.original = original


class AgentGraphRunner:
    """LangGraph runner with a sequential fallback for degraded test/runtime environments."""

    def __init__(self, *, graph_name: str = "agent") -> None:
        self.graph_name = graph_name
        self.backend = "langgraph" if importlib.util.find_spec("langgraph") else "sequential_langgraph_compat"

    def run(self, state: dict[str, Any], nodes: list[GraphNodeSpec | GraphNode]) -> dict[str, Any]:
        specs = [_coerce_spec(node) for node in nodes]
        state = dict(state)
        state["graph_backend"] = self.backend
        state["graph_run"] = _new_graph_run(graph_name=self.graph_name, backend=self.backend)
        started = time.perf_counter()
        try:
            if self.backend == "langgraph":
                state = self._run_langgraph(state, specs)
            else:
                state = self._run_sequential(state, specs)
        except GraphExecutionError as caught:
            _finish_graph_run(caught.state, started)
            raise
        _finish_graph_run(state, started)
        state["graph_nodes"] = [node.name for node in specs]
        return state

    def _run_langgraph(self, state: dict[str, Any], nodes: list[GraphNodeSpec]) -> dict[str, Any]:
        from langgraph.graph import END, START, StateGraph

        graph = StateGraph(dict)
        previous = START
        for spec in nodes:
            graph.add_node(spec.name, self._wrapped_node(spec))
            graph.add_edge(previous, spec.name)
            previous = spec.name
        graph.add_edge(previous, END)
        return graph.compile().invoke(state)

    def _run_sequential(self, state: dict[str, Any], nodes: list[GraphNodeSpec]) -> dict[str, Any]:
        for spec in nodes:
            state = self._wrapped_node(spec)(state)
        return state

    def _wrapped_node(self, spec: GraphNodeSpec) -> GraphCallable:
        def wrapped(state: dict[str, Any]) -> dict[str, Any]:
            node_started = time.perf_counter()
            input_summary = _summarize_state(state)
            error: str | None = None
            try:
                next_state = spec.func(state)
            except Exception as caught:
                next_state = dict(state)
                error = f"{type(caught).__name__}: {caught}"
                _record_node(
                    next_state,
                    spec=spec,
                    started=node_started,
                    input_summary=input_summary,
                    output_summary=_summarize_state(next_state),
                    error=error,
                )
                raise GraphExecutionError(error, state=next_state, original=caught) from caught
            _record_node(
                next_state,
                spec=spec,
                started=node_started,
                input_summary=input_summary,
                output_summary=_summarize_state(next_state),
                error=error,
            )
            return next_state

        return wrapped


def _coerce_spec(node: GraphNodeSpec | GraphNode) -> GraphNodeSpec:
    if isinstance(node, GraphNodeSpec):
        return node
    return GraphNodeSpec(name=node[0], func=node[1], public_name=node[0])


def _new_graph_run(*, graph_name: str, backend: str) -> dict[str, Any]:
    started_at = datetime.now(timezone.utc).isoformat()
    return {
        "graph_id": f"{graph_name}-{uuid4().hex[:8]}",
        "graph_name": graph_name,
        "graph_backend": backend,
        "nodes": [],
        "blocked_at": None,
        "total_duration_ms": 0,
        "started_at": started_at,
        "finished_at": None,
    }


def _finish_graph_run(state: dict[str, Any], started: float) -> None:
    graph_run = state.setdefault("graph_run", {})
    graph_run["finished_at"] = datetime.now(timezone.utc).isoformat()
    graph_run["total_duration_ms"] = max(0, int((time.perf_counter() - started) * 1000))
    graph_run.setdefault("graph_backend", state.get("graph_backend", "unknown"))
    graph_run.setdefault("nodes", [])
    state["graph_run"] = graph_run


def _record_node(
    state: dict[str, Any],
    *,
    spec: GraphNodeSpec,
    started: float,
    input_summary: dict[str, Any],
    output_summary: dict[str, Any],
    error: str | None,
) -> None:
    graph_run = state.setdefault("graph_run", _new_graph_run(graph_name="unknown", backend=state.get("graph_backend", "unknown")))
    blocked = bool(state.get(spec.blocked_state_key)) if spec.blocked_state_key else False
    public_name = spec.public_name or spec.name
    node_record = {
        "name": spec.name,
        "public_name": public_name,
        "duration_ms": max(0, int((time.perf_counter() - started) * 1000)),
        "blocked": blocked,
        "input_summary": input_summary,
        "output_summary": output_summary,
        "error": error,
        "metadata": {
            "canonical_node": spec.name,
            "public_node": public_name,
            **_guard_metadata(state),
        },
    }
    graph_run.setdefault("nodes", []).append(node_record)
    if (blocked or error) and graph_run.get("blocked_at") is None:
        graph_run["blocked_at"] = public_name
    state["graph_run"] = graph_run


def _guard_metadata(state: dict[str, Any]) -> dict[str, Any]:
    pipeline = state.get("pipeline")
    if pipeline is not None and hasattr(pipeline, "runtime_metadata"):
        try:
            return dict(pipeline.runtime_metadata())
        except Exception:
            return {}
    guard_engine = state.get("guard_engine")
    if guard_engine:
        return {"guard_engine": guard_engine}
    return {}


def _summarize_state(state: dict[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "keys": sorted(key for key in state if not key.startswith("_"))[:24],
    }
    request = state.get("request")
    if request is not None:
        for key in ("scenario_id", "adapter", "target_surface", "guard_profile", "model"):
            value = getattr(request, key, None)
            if value is not None:
                summary[key] = value
        probes = getattr(request, "probes", None)
        if probes is not None:
            summary["probes_count"] = len(probes)
    if state.get("user_message"):
        summary["user_message_chars"] = len(str(state.get("user_message")))
    if state.get("trace") is not None:
        summary["trace_steps"] = len(state.get("trace") or [])
    tool_call = state.get("tool_call")
    if tool_call is not None:
        summary["tool_name"] = getattr(tool_call, "tool_name", None)
    if state.get("tool_verdicts") is not None:
        summary["tool_verdict_count"] = len(state.get("tool_verdicts") or [])
    if state.get("regression_payloads") is not None:
        summary["regression_payload_count"] = len(state.get("regression_payloads") or [])
    if state.get("formal_response") is not None:
        formal_response = state["formal_response"]
        summary["experiment_id"] = getattr(formal_response, "experiment_id", None)
    if state.get("asr_comparison") is not None:
        summary["asr_surfaces"] = sorted((state.get("asr_comparison") or {}).keys())
    if state.get("candidate_guard_pack") is not None:
        summary["guard_pack_rule_count"] = len((state.get("candidate_guard_pack") or {}).get("rule_templates") or [])
    if state.get("files") is not None:
        summary["file_keys"] = sorted((state.get("files") or {}).keys())
    if state.get("response") is not None:
        summary["response_chars"] = len(str(state.get("response") or ""))
    return summary
