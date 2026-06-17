from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from typing import Any, Literal

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.agent.tool_agent import AgentRunRequest, AgentRunResponse, run_tool_agent
from app.config.settings import Settings
from app.config.settings import get_settings
from app.evals.defense_feedback import DefenseFeedbackRequest, DefenseFeedbackResponse, write_defense_feedback
from app.evals.garak import GarakEvalRunner
from app.evals.experiment_report import ExperimentReport, write_experiment_report
from app.evals.formal import (
    FORMAL_PROBES,
    FailureAnalysis,
    FormalExperimentResponse,
    ModelMatrixResponse,
    build_formal_experiment_response,
    build_model_matrix_row,
    unavailable_model_matrix_row,
)
from app.evals.paired import PairedEvalResponse, paired_response
from app.evals.promptfoo import PromptfooEvalRunner
from app.evals.runner import EvalArtifacts, LocalEvalRunner
from app.evals.report_store import ReportListResponse, ReportStore
from app.guardrails.pipeline import GuardMode, GuardrailPipeline
from app.models.provider import ModelProvider, OllamaModelProvider, OpenAICompatibleModelProvider, StubModelProvider
from app.rag.poisoning_demo import RAGPoisoningDemoRequest, RAGPoisoningDemoResult, run_rag_poisoning_demo
from app.rag.service import ChunkStrategy, PersistentHybridRAGService, RetrievalResult
from app.schemas.security import AgentStep, SessionSecurityReport, ToolCallVerdict
from app.tools.gateway import CallerContext, ToolGateway, default_tool_catalog


SUPPORTED_AUTODL_MODELS = ["qwen3:8b", "mistral-7b"]


class ChatRequest(BaseModel):
    message: str = Field(min_length=1)
    guard_mode: GuardMode = GuardMode.ENFORCE
    session_id: str = "local-session"


class ChatResponse(BaseModel):
    session_id: str
    blocked: bool
    response: str
    guard_results: list[dict]
    security_report: SessionSecurityReport
    model: str | None = None
    latency_ms: int | None = None


class ToolAuthorizeRequest(BaseModel):
    tool_name: str
    args: dict = Field(default_factory=dict)
    caller_role: str = "public"
    user_id: str = "local-user"
    session_id: str | None = None


class RAGIngestRequest(BaseModel):
    document_id: str = Field(min_length=1)
    text: str = Field(min_length=1)
    allowed_roles: list[str] = Field(default_factory=lambda: ["public"])
    chunk_strategy: ChunkStrategy = ChunkStrategy.SENTENCE
    collection: str = "default"
    source_type: str = "manual"
    trust_level: str = "standard"
    poison_label: str = "unknown"


class RAGIngestResponse(BaseModel):
    document_id: str
    chunks_indexed: int


class RAGQueryRequest(BaseModel):
    query: str = Field(min_length=1)
    caller_role: str = "public"
    limit: int = Field(default=5, ge=1, le=5)


class OpenAIChatMessage(BaseModel):
    role: str
    content: str


class OpenAIChatCompletionRequest(BaseModel):
    model: str = "local-agent"
    messages: list[OpenAIChatMessage]
    guard_mode: GuardMode = GuardMode.ENFORCE
    max_tokens: int | None = Field(default=None, ge=1, le=4096)
    temperature: float | None = Field(default=None, ge=0.0, le=2.0)


class EvalRunRequest(BaseModel):
    adapter: Literal["local", "garak", "promptfoo"] = "local"
    probes: list[str] = Field(default_factory=lambda: ["injection"])
    guard_mode: GuardMode = GuardMode.ENFORCE
    model: str | None = None
    garak_probe_spec: str | None = None
    garak_detector_spec: str | None = None


class PairedEvalRunRequest(BaseModel):
    adapter: Literal["local", "garak", "promptfoo"] = "local"
    probes: list[str] = Field(
        default_factory=lambda: [
            "direct_injection",
            "role_takeover",
            "long_context_hijack",
            "rag_poisoning",
            "web_poisoning",
            "tool_return_poisoning",
            "unauthorized_tool_call",
        ]
    )
    model: str | None = None
    garak_probe_spec: str | None = None
    garak_detector_spec: str | None = None


class FormalExperimentRequest(BaseModel):
    adapter: Literal["local", "garak", "promptfoo"] = "local"
    probes: list[str] = Field(default_factory=lambda: list(FORMAL_PROBES))
    model: str | None = None
    garak_probe_spec: str | None = None
    garak_detector_spec: str | None = None


class SecurityCycleRequest(FormalExperimentRequest):
    include_regression_payloads: bool = False
    regression_payloads: list[dict] = Field(default_factory=list)
    target_surface: Literal["chat", "rag", "tool_agent", "all"] = "all"
    guard_profile: Literal["baseline", "custom_rules", "semantic", "tool_guard", "rag_isolation", "combined"] = "combined"
    guard_pack: str | None = None


class ModelMatrixRequest(BaseModel):
    adapter: Literal["local", "garak", "promptfoo"] = "local"
    models: list[str] = Field(default_factory=lambda: ["qwen3:8b", "llama-3.1-8b", "mistral-7b", "deepseek-r1-distill-qwen-7b"])
    probes: list[str] = Field(default_factory=lambda: list(FORMAL_PROBES))
    garak_probe_spec: str | None = None
    garak_detector_spec: str | None = None


class EvalRunResponse(BaseModel):
    run: dict
    files: dict[str, str]
    report_dir: str


class ExperimentReportRequest(BaseModel):
    baseline_run_id: str
    guarded_run_id: str


class ExperimentReportResponse(BaseModel):
    baseline_run_id: str
    guarded_run_id: str
    markdown: str
    html: str
    files: dict[str, str]


class SecurityCycleResponse(BaseModel):
    experiment_id: str
    paired: PairedEvalResponse
    report: ExperimentReport
    defense_feedback: DefenseFeedbackResponse
    failure_analysis: FailureAnalysis
    rule_hits: dict[str, int]
    next_steps: list[str]
    next_round_payloads: list[dict]
    regression_payloads_used: list[dict]
    regression_payload_source: str | None = None
    target_surface: Literal["chat", "rag", "tool_agent", "all"] = "all"
    guard_profile: str = "combined"
    asr_comparison: dict[str, dict[str, float | int]] = Field(default_factory=dict)
    candidate_guard_pack: dict = Field(default_factory=dict)
    files: dict[str, str] = Field(default_factory=dict)


class DirectDefenseFeedbackRequest(BaseModel):
    run_id: str | None = None
    failed_samples: list[dict] = Field(default_factory=list)


class AutoDLModelStatusResponse(BaseModel):
    active_model: str
    available_models: list[str]
    supported_models: list[str]
    model_provider: str
    switchable: bool


class AutoDLModelSwitchRequest(BaseModel):
    model: str


class AutoDLModelSwitchResponse(BaseModel):
    previous_model: str
    active_model: str
    status: str
    commands: list[str]
    message: str


def frontend_dist_dir() -> Path:
    return Path(__file__).resolve().parents[3] / "web" / "dist"

def mount_static_frontend(app: FastAPI) -> None:
    dist_dir = frontend_dist_dir()
    index_path = dist_dir / "index.html"
    assets_dir = dist_dir / "assets"
    if not index_path.exists():
        return
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=assets_dir), name="frontend-assets")

    @app.get("/", include_in_schema=False)
    def serve_frontend_index() -> FileResponse:
        return FileResponse(index_path)


def build_model_provider(settings: Settings, model_override: str | None = None) -> ModelProvider:
    provider_name = settings.model_provider.strip().lower()
    if provider_name == "ollama":
        return OllamaModelProvider(
            base_url=settings.ollama_base_url,
            model_name=model_override or settings.ollama_model,
        )
    if provider_name in {"openai", "openai_compatible", "autodl"}:
        return OpenAICompatibleModelProvider(
            base_url=settings.openai_base_url,
            model_name=model_override or settings.openai_model,
            api_key=settings.openai_api_key,
        )
    return StubModelProvider(model_name=model_override or settings.ollama_model)


def runtime_model_status(settings: Settings, model_override: str | None = None) -> dict[str, object]:
    provider_name = settings.model_provider.strip().lower()
    if provider_name == "ollama":
        return {
            "model_provider": "ollama",
            "model_name": model_override or settings.ollama_model,
            "inference_base_url": settings.ollama_base_url,
            "local_inference": True,
        }
    if provider_name in {"openai", "openai_compatible", "autodl"}:
        return {
            "model_provider": provider_name,
            "model_name": model_override or settings.openai_model,
            "inference_base_url": settings.openai_base_url,
            "local_inference": False,
        }
    return {
        "model_provider": "stub",
        "model_name": settings.ollama_model,
        "inference_base_url": None,
        "local_inference": False,
    }


def run_model_manager(action: str, model: str) -> str:
    root = Path(__file__).resolve().parents[3]
    script = root / "scripts" / "manage-autodl-models.sh"
    if action not in {"status", "smoke", "start", "stop"}:
        raise RuntimeError(f"Unsupported model manager action: {action}")
    if model not in SUPPORTED_AUTODL_MODELS:
        raise RuntimeError(f"Unsupported model: {model}")
    completed = subprocess.run(
        [str(script), action, model],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=240,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stdout.strip() or f"{action} {model} failed")
    return completed.stdout


def wait_for_model_available(settings: Settings, model: str, timeout_seconds: int = 180) -> bool:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        available = available_model_names(settings)
        if model in (available or set()):
            return True
        time.sleep(5)
    return False


def available_model_names(settings: Settings) -> set[str] | None:
    provider_name = settings.model_provider.strip().lower()
    if provider_name not in {"openai", "openai_compatible", "autodl"}:
        return None
    try:
        response = httpx.get(
            f"{settings.openai_base_url.rstrip('/')}/models",
            headers={"Authorization": f"Bearer {settings.openai_api_key or 'dummy'}"},
            timeout=5.0,
        )
        response.raise_for_status()
    except Exception:
        return set()
    payload = response.json()
    return {
        str(item.get("id"))
        for item in payload.get("data", [])
        if item.get("id")
    }


def guarded_chat(
    *,
    messages: list[dict[str, str]],
    guard_mode: GuardMode,
    session_id: str,
    provider: ModelProvider,
    max_tokens: int | None = None,
    temperature: float | None = None,
) -> ChatResponse:
    user_message = next(
        (message["content"] for message in reversed(messages) if message["role"] == "user"),
        "",
    )
    pipeline = GuardrailPipeline(mode=guard_mode)
    input_result = pipeline.check_input(user_message)
    guard_results = [input_result.model_dump(mode="json")]

    if input_result.action == "block":
        step = AgentStep(
            step_index=0,
            guardrail_intervention=True,
            final_action="refusal",
        )
        return ChatResponse(
            session_id=session_id,
            blocked=True,
            response="I cannot comply with that request.",
            guard_results=guard_results,
            security_report=SessionSecurityReport(session_id=session_id, steps=[step]),
        )

    model_response = provider.chat(
        messages,
        max_tokens=max_tokens,
        temperature=temperature,
    )
    output_result = pipeline.check_output(model_response.content)
    guard_results.append(output_result.model_dump(mode="json"))
    blocked = output_result.action == "block"
    step = AgentStep(
        step_index=0,
        guardrail_intervention=output_result.triggered,
        final_action="refusal" if blocked else "text_response",
    )
    return ChatResponse(
        session_id=session_id,
        blocked=blocked,
        response="I cannot comply with that request." if blocked else model_response.content,
        guard_results=guard_results,
        security_report=SessionSecurityReport(session_id=session_id, steps=[step]),
        model=model_response.model,
        latency_ms=model_response.latency_ms,
    )


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="LLM Security Guardrail Platform",
        version="0.1.0",
    )
    mount_static_frontend(app)
    rag_service = PersistentHybridRAGService(
        store_path=f"{settings.chroma_persist_directory}/rag-store.json"
    )
    eval_artifacts: dict[str, EvalArtifacts] = {}
    runtime_state = {"active_model": settings.openai_model or settings.ollama_model}

    def active_model_name(available_models: set[str] | None = None) -> str:
        if available_models:
            online_supported = sorted(model for model in available_models if model in SUPPORTED_AUTODL_MODELS)
            current = str(runtime_state["active_model"])
            if current in online_supported:
                return current
            if len(online_supported) == 1:
                runtime_state["active_model"] = online_supported[0]
                return online_supported[0]
        return str(runtime_state["active_model"])

    def run_eval_artifacts(
        *,
        adapter: Literal["local", "garak", "promptfoo"],
        probes: list[str],
        guard_mode: GuardMode,
        model: str | None = None,
        garak_probe_spec: str | None = None,
        garak_detector_spec: str | None = None,
        regression_payloads: list[dict] | None = None,
    ) -> EvalArtifacts:
        if adapter == "garak":
            runner = GarakEvalRunner(
                reports_dir=Path(settings.reports_dir),
                service_base_url=settings.service_base_url,
                model_name=model or settings.openai_model or settings.ollama_model,
                timeout_seconds=settings.garak_timeout_seconds,
            )
            return runner.run_with_artifacts(
                probes=probes,
                guard_mode=guard_mode,
                garak_probe_spec=garak_probe_spec,
                garak_detector_spec=garak_detector_spec,
            )
        if adapter == "promptfoo":
            runner = PromptfooEvalRunner(
                reports_dir=Path(settings.reports_dir),
                service_base_url=settings.service_base_url,
                model_name=model or settings.openai_model or settings.ollama_model,
            )
            return runner.run_with_artifacts(
                probes=probes,
                guard_mode=guard_mode,
            )
        runner = LocalEvalRunner(
            provider=build_model_provider(settings, model_override=model or active_model_name()),
            reports_dir=Path(settings.reports_dir),
        )
        local_kwargs = {"probes": probes, "guard_mode": guard_mode}
        if regression_payloads:
            local_kwargs["regression_payloads"] = regression_payloads
        return runner.run_with_artifacts(**local_kwargs)

    def runtime_inference_base_url() -> str:
        provider_name = settings.model_provider.strip().lower()
        if provider_name in {"openai", "openai_compatible", "autodl"}:
            return settings.openai_base_url
        return settings.ollama_base_url

    def run_formal_experiment_artifacts(
        request: FormalExperimentRequest,
        *,
        regression_payloads: list[dict] | None = None,
    ) -> FormalExperimentResponse:
        try:
            baseline = run_eval_artifacts(
                adapter=request.adapter,
                probes=request.probes,
                guard_mode=GuardMode.OFF,
                model=request.model,
                garak_probe_spec=request.garak_probe_spec,
                garak_detector_spec=request.garak_detector_spec,
                regression_payloads=regression_payloads,
            )
            guarded = run_eval_artifacts(
                adapter=request.adapter,
                probes=request.probes,
                guard_mode=GuardMode.ENFORCE,
                model=request.model,
                garak_probe_spec=request.garak_probe_spec,
                garak_detector_spec=request.garak_detector_spec,
                regression_payloads=regression_payloads,
            )
        except RuntimeError as caught:
            raise HTTPException(status_code=400, detail=str(caught)) from caught
        except Exception as caught:
            raise HTTPException(
                status_code=502,
                detail=f"Formal experiment failed: {type(caught).__name__}: {caught}",
            ) from caught

        eval_artifacts[baseline.run.run_id] = baseline
        eval_artifacts[guarded.run.run_id] = guarded
        defense_feedback = write_defense_feedback(guarded)
        report = write_experiment_report(
            baseline=baseline,
            guarded=guarded,
            model_name=request.model or active_model_name(),
            provider=settings.model_provider,
            inference_base_url=runtime_inference_base_url(),
            defense_feedback=defense_feedback,
        )
        return build_formal_experiment_response(
            baseline=baseline,
            guarded=guarded,
            report=report,
            defense_feedback=defense_feedback,
        )


    def load_regression_payloads(request: SecurityCycleRequest) -> tuple[list[dict], str | None]:
        explicit_payloads = _valid_regression_payloads(request.regression_payloads)
        if explicit_payloads:
            return explicit_payloads, "request"
        if not request.include_regression_payloads:
            return [], None

        for report in ReportStore(settings.reports_dir).list_reports():
            next_payloads_path = report.files.get("next_payloads")
            if not next_payloads_path:
                continue
            payloads = _read_regression_payloads(Path(next_payloads_path))
            if payloads:
                return payloads, report.run_id
        return [], None

    @app.get("/health")
    def health() -> dict[str, object]:
        return {
            "status": "ok",
            "service": settings.service_name,
            "assets_root": settings.assets_root,
            "service_base_url": settings.service_base_url,
            **runtime_model_status(settings, model_override=active_model_name()),
        }

    @app.post("/chat", response_model=ChatResponse)
    def chat(request: ChatRequest) -> ChatResponse:
        return guarded_chat(
            messages=[{"role": "user", "content": request.message}],
            guard_mode=request.guard_mode,
            session_id=request.session_id,
            provider=build_model_provider(settings, model_override=active_model_name()),
        )

    @app.post("/v1/chat/completions")
    def openai_chat_completions(request: OpenAIChatCompletionRequest) -> dict:
        chat_response = guarded_chat(
            messages=[message.model_dump() for message in request.messages],
            guard_mode=request.guard_mode,
            session_id="openai-compatible-session",
            provider=build_model_provider(settings, model_override=request.model),
            max_tokens=request.max_tokens,
            temperature=request.temperature,
        )
        return {
            "id": "chatcmpl-local",
            "object": "chat.completion",
            "model": request.model,
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": chat_response.response,
                    },
                    "finish_reason": "stop",
                }
            ],
            "security": {
                "blocked": chat_response.blocked,
                "guard_results": chat_response.guard_results,
                "security_report": chat_response.security_report.model_dump(mode="json"),
            },
        }

    @app.post("/tools/authorize", response_model=ToolCallVerdict)
    def authorize_tool(request: ToolAuthorizeRequest) -> ToolCallVerdict:
        gateway = ToolGateway(default_tool_catalog())
        return gateway.authorize(
            request.tool_name,
            request.args,
            CallerContext(
                caller_role=request.caller_role,
                user_id=request.user_id,
                session_id=request.session_id,
            ),
        )

    @app.get("/models/autodl-status", response_model=AutoDLModelStatusResponse)
    def autodl_model_status() -> AutoDLModelStatusResponse:
        available = available_model_names(settings)
        provider_name = settings.model_provider.strip().lower()
        return AutoDLModelStatusResponse(
            active_model=active_model_name(available),
            available_models=sorted(available or []),
            supported_models=list(SUPPORTED_AUTODL_MODELS),
            model_provider=provider_name,
            switchable=provider_name in {"autodl", "openai_compatible", "openai"},
        )

    @app.post("/models/switch", response_model=AutoDLModelSwitchResponse)
    def switch_autodl_model(request: AutoDLModelSwitchRequest) -> AutoDLModelSwitchResponse:
        previous = active_model_name(available_model_names(settings))
        target = request.model
        if target not in SUPPORTED_AUTODL_MODELS:
            raise HTTPException(status_code=400, detail=f"Unsupported model: {target}")
        if previous == target:
            return AutoDLModelSwitchResponse(
                previous_model=previous,
                active_model=target,
                status="ready",
                commands=[],
                message=f"{target} is already active.",
            )
        commands = [f"stop {previous}", f"start {target}"]
        try:
            run_model_manager("stop", previous)
            run_model_manager("start", target)
        except RuntimeError as caught:
            raise HTTPException(status_code=502, detail=str(caught)) from caught
        if not wait_for_model_available(settings, target):
            raise HTTPException(status_code=504, detail=f"Timed out waiting for {target} to become available.")
        runtime_state["active_model"] = target
        return AutoDLModelSwitchResponse(
            previous_model=previous,
            active_model=target,
            status="ready",
            commands=commands,
            message=f"Switched AutoDL vLLM from {previous} to {target}.",
        )

    @app.post("/agent/run", response_model=AgentRunResponse)
    def run_agent(request: AgentRunRequest) -> AgentRunResponse:
        return run_tool_agent(request=request, rag_service=rag_service)

    @app.post("/rag/ingest", response_model=RAGIngestResponse)
    def rag_ingest(request: RAGIngestRequest) -> RAGIngestResponse:
        chunks = rag_service.ingest_text(
            document_id=request.document_id,
            text=request.text,
            allowed_roles=request.allowed_roles,
            chunk_strategy=request.chunk_strategy,
            collection=request.collection,
            source_type=request.source_type,
            trust_level=request.trust_level,
            poison_label=request.poison_label,
        )
        return RAGIngestResponse(
            document_id=request.document_id,
            chunks_indexed=len(chunks),
        )

    @app.post("/rag/query", response_model=RetrievalResult)
    def rag_query(request: RAGQueryRequest) -> RetrievalResult:
        return rag_service.query(
            query=request.query,
            caller_role=request.caller_role,
            limit=request.limit,
        )

    @app.post("/rag/poisoning-demo", response_model=RAGPoisoningDemoResult)
    def rag_poisoning_demo(request: RAGPoisoningDemoRequest) -> RAGPoisoningDemoResult:
        return run_rag_poisoning_demo(
            rag_service=rag_service,
            request=request,
        )

    @app.post("/eval/run", response_model=EvalRunResponse)
    def run_eval(request: EvalRunRequest) -> EvalRunResponse:
        try:
            artifacts = run_eval_artifacts(
                adapter=request.adapter,
                probes=request.probes,
                guard_mode=request.guard_mode,
                model=request.model,
                garak_probe_spec=request.garak_probe_spec,
                garak_detector_spec=request.garak_detector_spec,
            )
        except RuntimeError as caught:
            raise HTTPException(status_code=400, detail=str(caught)) from caught
        eval_artifacts[artifacts.run.run_id] = artifacts
        return EvalRunResponse(
            run=artifacts.run.model_dump(mode="json"),
            files=artifacts.files,
            report_dir=artifacts.report_dir,
        )

    @app.post("/eval/paired-run", response_model=PairedEvalResponse)
    def run_paired_eval(request: PairedEvalRunRequest) -> PairedEvalResponse:
        try:
            baseline = run_eval_artifacts(
                adapter=request.adapter,
                probes=request.probes,
                guard_mode=GuardMode.OFF,
                model=request.model,
                garak_probe_spec=request.garak_probe_spec,
                garak_detector_spec=request.garak_detector_spec,
            )
            guarded = run_eval_artifacts(
                adapter=request.adapter,
                probes=request.probes,
                guard_mode=GuardMode.ENFORCE,
                model=request.model,
                garak_probe_spec=request.garak_probe_spec,
                garak_detector_spec=request.garak_detector_spec,
            )
        except RuntimeError as caught:
            raise HTTPException(status_code=400, detail=str(caught)) from caught
        eval_artifacts[baseline.run.run_id] = baseline
        eval_artifacts[guarded.run.run_id] = guarded
        return paired_response(baseline=baseline, guarded=guarded)

    @app.post("/experiments/formal-run", response_model=FormalExperimentResponse)
    def run_formal_experiment(request: FormalExperimentRequest) -> FormalExperimentResponse:
        return run_formal_experiment_artifacts(request)

    @app.post("/experiments/security-cycle", response_model=SecurityCycleResponse)
    def run_security_cycle(request: SecurityCycleRequest) -> SecurityCycleResponse:
        regression_payloads, regression_source = load_regression_payloads(request)
        formal_response = run_formal_experiment_artifacts(
            FormalExperimentRequest(
                adapter=request.adapter,
                probes=request.probes,
                model=request.model,
                garak_probe_spec=request.garak_probe_spec,
                garak_detector_spec=request.garak_detector_spec,
            ),
            regression_payloads=regression_payloads,
        )
        asr_comparison = build_surface_asr_comparison(
            baseline=formal_response.paired.baseline["run"],
            guarded=formal_response.paired.guarded["run"],
            target_surface=request.target_surface,
        )
        candidate_guard_pack = build_candidate_guard_pack(
            feedback=formal_response.defense_feedback,
            guard_profile=request.guard_profile,
            target_surface=request.target_surface,
            source_guard_pack=request.guard_pack,
        )
        cycle_files = write_security_cycle_artifacts(
            guarded_report_dir=Path(formal_response.paired.guarded["report_dir"]),
            candidate_guard_pack=candidate_guard_pack,
            asr_comparison=asr_comparison,
        )
        return SecurityCycleResponse(
            **formal_response.model_dump(),
            next_round_payloads=formal_response.defense_feedback.next_round_payloads,
            regression_payloads_used=regression_payloads,
            regression_payload_source=regression_source,
            target_surface=request.target_surface,
            guard_profile=request.guard_profile,
            asr_comparison=asr_comparison,
            candidate_guard_pack=candidate_guard_pack,
            files=cycle_files,
        )

    @app.post("/experiments/model-matrix", response_model=ModelMatrixResponse)
    def run_model_matrix(request: ModelMatrixRequest) -> ModelMatrixResponse:
        rows = []
        available_models = available_model_names(settings)
        for model in request.models:
            if available_models is not None and model not in available_models:
                rows.append(unavailable_model_matrix_row(model=model))
                continue
            formal_response = run_formal_experiment_artifacts(
                FormalExperimentRequest(
                    adapter=request.adapter,
                    probes=request.probes,
                    model=model,
                    garak_probe_spec=request.garak_probe_spec,
                    garak_detector_spec=request.garak_detector_spec,
                )
            )
            rows.append(build_model_matrix_row(model=model, response=formal_response))
        return ModelMatrixResponse(matrix=rows)

    @app.post("/experiments/defense-feedback", response_model=DefenseFeedbackResponse)
    def create_defense_feedback(request: DirectDefenseFeedbackRequest) -> DefenseFeedbackResponse:
        if request.run_id:
            try:
                artifacts = eval_artifacts.get(request.run_id) or ReportStore(settings.reports_dir).load_artifacts(request.run_id)
            except FileNotFoundError:
                raise HTTPException(status_code=404, detail=f"Report '{request.run_id}' not found.")
            return write_defense_feedback(artifacts)
        return write_defense_feedback(
            DefenseFeedbackRequest(
                run_id=request.run_id,
                failed_samples=request.failed_samples,
            )
        )

    @app.get("/reports", response_model=ReportListResponse)
    def list_reports() -> ReportListResponse:
        return ReportListResponse(reports=ReportStore(settings.reports_dir).list_reports())

    @app.get("/reports/{run_id}", response_model=EvalRunResponse)
    def get_report(run_id: str) -> EvalRunResponse:
        artifacts = eval_artifacts.get(run_id)
        if artifacts is None:
            try:
                artifacts = ReportStore(settings.reports_dir).load_artifacts(run_id)
            except FileNotFoundError:
                raise HTTPException(status_code=404, detail=f"Report '{run_id}' not found.")
        return EvalRunResponse(
            run=artifacts.run.model_dump(mode="json"),
            files=artifacts.files,
            report_dir=artifacts.report_dir,
        )

    @app.get("/report-files/{run_id}/{file_key}")
    def get_report_file(run_id: str, file_key: str) -> FileResponse:
        try:
            path = ReportStore(settings.reports_dir).report_file_path(run_id, file_key)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail=f"Report file '{file_key}' for '{run_id}' not found.")
        return FileResponse(
            path,
            media_type=_report_file_media_type(file_key, path),
            filename=path.name,
            content_disposition_type="inline",
        )

    @app.post("/reports/experiment", response_model=ExperimentReportResponse)
    def create_experiment_report(request: ExperimentReportRequest) -> ExperimentReportResponse:
        store = ReportStore(settings.reports_dir)
        baseline = eval_artifacts.get(request.baseline_run_id)
        guarded = eval_artifacts.get(request.guarded_run_id)
        try:
            if baseline is None:
                baseline = store.load_artifacts(request.baseline_run_id)
            if guarded is None:
                guarded = store.load_artifacts(request.guarded_run_id)
        except FileNotFoundError as caught:
            raise HTTPException(status_code=404, detail=f"Report '{caught.args[0]}' not found.")

        report = write_experiment_report(
            baseline=baseline,
            guarded=guarded,
            model_name=settings.openai_model or settings.ollama_model,
            provider=settings.model_provider,
            inference_base_url=settings.openai_base_url if settings.model_provider.strip().lower() in {"openai", "openai_compatible", "autodl"} else settings.ollama_base_url,
            defense_feedback=write_defense_feedback(guarded),
        )
        return ExperimentReportResponse(**report.model_dump())

    return app


def _valid_regression_payloads(payloads: list[dict]) -> list[dict]:
    valid: list[dict] = []
    for payload in payloads:
        text = str(payload.get("payload") or payload.get("prompt") or "").strip()
        if not text:
            continue
        normalized = dict(payload)
        normalized["payload"] = text
        normalized.setdefault("probe", payload.get("failure_type") or "regression_payload")
        normalized.setdefault("expected_guard", "block")
        valid.append(normalized)
    return valid


def _read_regression_payloads(path: Path) -> list[dict]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(payload, list):
        return []
    return _valid_regression_payloads([item for item in payload if isinstance(item, dict)])


def build_surface_asr_comparison(
    *,
    baseline: dict[str, Any],
    guarded: dict[str, Any],
    target_surface: str,
) -> dict[str, dict[str, float | int]]:
    baseline_results = list(baseline.get("results") or [])
    guarded_results = list(guarded.get("results") or [])
    surfaces = ["overall", "prompt", "rag", "tool", "agent"]
    comparison: dict[str, dict[str, float | int]] = {}
    for surface in surfaces:
        before = _surface_results(baseline_results, surface)
        after = _surface_results(guarded_results, surface)
        if target_surface != "all" and surface not in {"overall", _target_surface_to_metric(target_surface)}:
            continue
        before_asr = _asr(before)
        after_asr = _asr(after)
        reduction_pct = 0.0
        if before_asr > 0:
            reduction_pct = max(0.0, (before_asr - after_asr) / before_asr * 100)
        comparison[surface] = {
            "before_asr": round(before_asr, 4),
            "after_asr": round(after_asr, 4),
            "reduction_pct": round(reduction_pct, 2),
            "total": len(after),
        }
    if "agent" in comparison:
        comparison["agent"]["agent_unsafe_action_rate"] = comparison["agent"]["after_asr"]
    return comparison


def build_candidate_guard_pack(
    *,
    feedback: DefenseFeedbackResponse,
    guard_profile: str,
    target_surface: str,
    source_guard_pack: str | None,
) -> dict[str, Any]:
    rule_templates: list[dict[str, Any]] = []
    semantic_expansions: list[str] = []
    isolation_sources: list[str] = []
    for suggestion in feedback.suggestions:
        rule_templates.extend(suggestion.rule_templates)
        semantic_expansions.extend(suggestion.semantic_expansions)
        isolation_sources.extend(suggestion.isolation_sources)
    return {
        "schema_version": 1,
        "source_run_id": feedback.run_id,
        "source_guard_pack": source_guard_pack,
        "guard_profile": guard_profile,
        "target_surface": target_surface,
        "rule_templates": rule_templates,
        "semantic_expansions": sorted(set(semantic_expansions)),
        "isolation_sources": sorted(set(isolation_sources)),
        "tool_policy_notes": [
            "ToolGateway remains the deterministic authorization boundary.",
            "Candidate guard packs are review artifacts and do not modify source code automatically.",
        ],
        "next_round_payloads": feedback.next_round_payloads,
    }


def write_security_cycle_artifacts(
    *,
    guarded_report_dir: Path,
    candidate_guard_pack: dict[str, Any],
    asr_comparison: dict[str, dict[str, float | int]],
) -> dict[str, str]:
    guarded_report_dir.mkdir(parents=True, exist_ok=True)
    guard_pack_path = guarded_report_dir / "candidate-guard-pack.json"
    asr_path = guarded_report_dir / "asr-comparison.json"
    guard_pack_path.write_text(
        json.dumps(candidate_guard_pack, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    asr_path.write_text(
        json.dumps(asr_comparison, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return {
        "candidate_guard_pack": str(guard_pack_path),
        "asr_comparison": str(asr_path),
    }


def _surface_results(results: list[dict[str, Any]], surface: str) -> list[dict[str, Any]]:
    if surface == "overall":
        return results
    return [result for result in results if _surface_for_probe(str(result.get("probe", ""))) == surface]


def _surface_for_probe(probe: str) -> str:
    text = probe.lower()
    if "rag" in text or "web" in text:
        return "rag"
    if "tool" in text or "unauthorized" in text or "export" in text:
        return "tool"
    if "agent" in text:
        return "agent"
    return "prompt"


def _target_surface_to_metric(target_surface: str) -> str:
    if target_surface == "tool_agent":
        return "agent"
    return target_surface


def _asr(results: list[dict[str, Any]]) -> float:
    if not results:
        return 0.0
    failed = sum(1 for result in results if not bool(result.get("blocked")))
    return failed / len(results)


app = create_app()


def _report_file_media_type(file_key: str, path: Path) -> str:
    if file_key.endswith("html") or path.suffix == ".html":
        return "text/html; charset=utf-8"
    if file_key == "json" or path.suffix == ".json":
        return "application/json"
    if path.suffix == ".csv":
        return "text/csv; charset=utf-8"
    if path.suffix in {".md", ".log", ".jsonl", ".yaml"}:
        return "text/plain; charset=utf-8"
    return "application/octet-stream"
