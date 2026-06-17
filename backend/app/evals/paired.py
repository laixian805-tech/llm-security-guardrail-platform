from __future__ import annotations

from pydantic import BaseModel

from app.evals.runner import EvalArtifacts


class PairedComparison(BaseModel):
    baseline_run_id: str
    guarded_run_id: str
    before_asr: float
    after_asr: float
    reduction_pct: float
    total_attacks: int
    failed_cases: list[dict]


class PairedEvalResponse(BaseModel):
    baseline: dict
    guarded: dict
    comparison: PairedComparison


def compare_artifacts(*, baseline: EvalArtifacts, guarded: EvalArtifacts) -> PairedComparison:
    before_asr = _pass_rate(baseline)
    after_asr = _pass_rate(guarded)
    reduction_pct = 0.0
    if before_asr > 0:
        reduction_pct = max(0.0, (before_asr - after_asr) / before_asr * 100)

    return PairedComparison(
        baseline_run_id=baseline.run.run_id,
        guarded_run_id=guarded.run.run_id,
        before_asr=round(before_asr, 4),
        after_asr=round(after_asr, 4),
        reduction_pct=round(reduction_pct, 2),
        total_attacks=guarded.run.summary.total_attacks if guarded.run.summary else len(guarded.run.results),
        failed_cases=[
            {
                "probe": result.probe,
                "category": result.category.value,
                "variant": result.variant,
                "prompt": result.prompt,
                "response": result.response,
                "guard_triggered": result.guard_triggered,
            }
            for result in guarded.run.results
            if not result.blocked
        ],
    )


def paired_response(*, baseline: EvalArtifacts, guarded: EvalArtifacts) -> PairedEvalResponse:
    return PairedEvalResponse(
        baseline={
            "run": baseline.run.model_dump(mode="json"),
            "files": baseline.files,
            "report_dir": baseline.report_dir,
        },
        guarded={
            "run": guarded.run.model_dump(mode="json"),
            "files": guarded.files,
            "report_dir": guarded.report_dir,
        },
        comparison=compare_artifacts(baseline=baseline, guarded=guarded),
    )


def _pass_rate(artifacts: EvalArtifacts) -> float:
    if artifacts.run.summary is not None:
        return artifacts.run.summary.pass_rate
    total = len(artifacts.run.results)
    if total == 0:
        return 0.0
    blocked = sum(1 for result in artifacts.run.results if result.blocked)
    return (total - blocked) / total
