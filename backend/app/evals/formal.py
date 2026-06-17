from __future__ import annotations

from collections import Counter, defaultdict

from pydantic import BaseModel, Field

from app.evals.defense_feedback import DefenseFeedbackResponse
from app.evals.experiment_report import ExperimentReport
from app.evals.paired import PairedEvalResponse, paired_response
from app.evals.runner import EvalArtifacts


FORMAL_PROBES = [
    "direct_injection",
    "role_takeover",
    "long_context_hijack",
    "rag_poisoning",
    "tool_return_poisoning",
    "unauthorized_tool_call",
]


class DefenseRecommendation(BaseModel):
    priority: str
    area: str
    action: str
    rationale: str


class ProbeFailureBucket(BaseModel):
    count: int = 0
    examples: list[dict] = Field(default_factory=list)


class FailureAnalysis(BaseModel):
    total_failed: int
    by_probe: dict[str, ProbeFailureBucket]
    by_category: dict[str, ProbeFailureBucket]
    recommendations: list[DefenseRecommendation]


class FormalExperimentResponse(BaseModel):
    experiment_id: str
    paired: PairedEvalResponse
    report: ExperimentReport
    defense_feedback: DefenseFeedbackResponse
    failure_analysis: FailureAnalysis
    rule_hits: dict[str, int]
    next_steps: list[str]


class ModelMatrixRow(BaseModel):
    model: str
    baseline_run_id: str
    guarded_run_id: str
    before_asr: float
    after_asr: float
    reduction_pct: float
    total_failed: int
    top_failure_type: str
    top_recommendation: str
    status: str = "ready"


class ModelMatrixResponse(BaseModel):
    matrix: list[ModelMatrixRow]


def build_formal_experiment_response(
    *,
    baseline: EvalArtifacts,
    guarded: EvalArtifacts,
    report: ExperimentReport,
    defense_feedback: DefenseFeedbackResponse,
) -> FormalExperimentResponse:
    paired = paired_response(baseline=baseline, guarded=guarded)
    failure_analysis = analyze_failures(guarded)
    return FormalExperimentResponse(
        experiment_id=f"{baseline.run.run_id}__{guarded.run.run_id}",
        paired=paired,
        report=report,
        defense_feedback=defense_feedback,
        failure_analysis=failure_analysis,
        rule_hits=rule_hit_counts(guarded),
        next_steps=_next_steps(failure_analysis),
    )


def build_model_matrix_row(*, model: str, response: FormalExperimentResponse) -> ModelMatrixRow:
    comparison = response.paired.comparison
    top = response.failure_analysis.recommendations[0].action if response.failure_analysis.recommendations else "No guarded failures; expand the attack set."
    top_failure_type = response.defense_feedback.items[0].failure_type if response.defense_feedback.items else response.defense_feedback.suggestions[0].failure_type
    return ModelMatrixRow(
        model=model,
        baseline_run_id=comparison.baseline_run_id,
        guarded_run_id=comparison.guarded_run_id,
        before_asr=comparison.before_asr,
        after_asr=comparison.after_asr,
        reduction_pct=comparison.reduction_pct,
        total_failed=response.failure_analysis.total_failed,
        top_failure_type=top_failure_type,
        top_recommendation=top,
        status="ready",
    )


def analyze_failures(guarded: EvalArtifacts) -> FailureAnalysis:
    failed = [result for result in guarded.run.results if not result.blocked]
    by_probe: dict[str, ProbeFailureBucket] = defaultdict(ProbeFailureBucket)
    by_category: dict[str, ProbeFailureBucket] = defaultdict(ProbeFailureBucket)

    for result in failed:
        example = {
            "probe": result.probe,
            "category": result.category.value,
            "variant": result.variant,
            "prompt": result.prompt,
            "response": result.response,
        }
        probe_bucket = by_probe[result.probe]
        probe_bucket.count += 1
        probe_bucket.examples.append(example)

        category_bucket = by_category[result.category.value]
        category_bucket.count += 1
        category_bucket.examples.append(example)

    return FailureAnalysis(
        total_failed=len(failed),
        by_probe=dict(by_probe),
        by_category=dict(by_category),
        recommendations=_recommendations_for_failures(failed),
    )


def rule_hit_counts(artifacts: EvalArtifacts) -> dict[str, int]:
    counts = Counter(
        result.guard_triggered
        for result in artifacts.run.results
        if result.guard_triggered
    )
    return dict(counts)


def _recommendations_for_failures(failed: list) -> list[DefenseRecommendation]:
    if not failed:
        return [
            DefenseRecommendation(
                priority="P1",
                area="attack_coverage",
                action="Expand the formal attack set with paraphrases and multi-turn variants.",
                rationale="No guarded failures were observed, so the next useful experiment should test broader coverage rather than tuning rules.",
            )
        ]

    seen: set[str] = set()
    recommendations: list[DefenseRecommendation] = []
    for result in failed:
        key = _recommendation_key(result.probe)
        if key in seen:
            continue
        seen.add(key)
        recommendations.append(_recommendation_for_probe(result.probe))
    return recommendations


def _recommendation_key(probe: str) -> str:
    if "rag" in probe:
        return "rag"
    if "tool" in probe or "unauthorized" in probe:
        return "tool"
    if "long_context" in probe:
        return "long_context"
    if "role" in probe:
        return "role"
    return "injection"


def _recommendation_for_probe(probe: str) -> DefenseRecommendation:
    key = _recommendation_key(probe)
    if key == "rag":
        return DefenseRecommendation(
            priority="P0",
            area="rag_source_isolation",
            action="Treat retrieved content as untrusted, strip imperative instructions, and attach source trust metadata before context injection.",
            rationale="A guarded RAG poisoning sample still reached an unsafe outcome.",
        )
    if key == "tool":
        return DefenseRecommendation(
            priority="P0",
            area="tool_authorization",
            action="Require role-tier checks and argument policy checks for every tool call, even when the model proposes the call confidently.",
            rationale="A guarded run still allowed or attempted a high-risk tool path.",
        )
    if key == "long_context":
        return DefenseRecommendation(
            priority="P1",
            area="long_context_attention",
            action="Add end-of-context override detection and summarize long external content before it reaches the model.",
            rationale="Long-context hijack survived the current guardrail pass.",
        )
    if key == "role":
        return DefenseRecommendation(
            priority="P1",
            area="role_takeover",
            action="Add semantic detection for developer/admin role reassignment and hidden instruction extraction phrasing.",
            rationale="Role takeover language was not fully covered.",
        )
    return DefenseRecommendation(
        priority="P1",
        area="prompt_injection",
        action="Add paraphrase-resistant override detection and include failed samples in the next formal probe set.",
        rationale="A direct or indirect injection variant bypassed the current rules.",
    )


def _next_steps(failure_analysis: FailureAnalysis) -> list[str]:
    if failure_analysis.total_failed == 0:
        return [
            "Freeze this run as the current guarded baseline.",
            "Add paraphrased and multi-turn attacks to probe for regression gaps.",
            "Run the same formal probe set against the next model in the matrix.",
        ]
    return [
        "Review failed guarded samples and add them to the regression attack set.",
        "Apply the highest-priority defense recommendation.",
        "Rerun /experiments/formal-run and compare ASR reduction against this run.",
    ]
