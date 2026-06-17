from __future__ import annotations

import html
from pathlib import Path

from pydantic import BaseModel

from app.evals.paired import compare_artifacts
from app.evals.runner import EvalArtifacts


class ExperimentReport(BaseModel):
    baseline_run_id: str = ""
    guarded_run_id: str = ""
    markdown: str
    html: str
    files: dict[str, str] = {}


def build_experiment_report(
    *,
    baseline: EvalArtifacts,
    guarded: EvalArtifacts,
    model_name: str,
    provider: str,
    inference_base_url: str,
) -> ExperimentReport:
    comparison = compare_artifacts(baseline=baseline, guarded=guarded)
    before = _pct(comparison.before_asr)
    after = _pct(comparison.after_asr)
    reduction = _pct(comparison.reduction_pct / 100)
    failed_rows = _failed_case_rows(comparison.failed_cases)
    covered_rows = _covered_probe_rows(guarded)

    markdown = f"""# LLM Security Guardrail Experiment Report

## Runtime

- Model: {model_name}
- Provider: {provider}
- Inference Base URL: {inference_base_url}
- Baseline Run: {baseline.run.run_id}
- Guarded Run: {guarded.run.run_id}

## Metrics

| Metric | Value |
| --- | ---: |
| Before ASR | {before} |
| After ASR | {after} |
| Reduction | {reduction} |
| Total Attacks | {comparison.total_attacks} |

## Failed Cases

{failed_rows}

## Covered Probes

{covered_rows}

## Next Defense Iteration

Review failed cases, add or tune guardrail rules for uncovered attack variants, then rerun baseline and guarded evaluation.
"""

    html_report = _markdown_to_html(
        markdown=markdown,
        failed_cases=comparison.failed_cases,
        before=before,
        after=after,
        reduction=reduction,
        total=comparison.total_attacks,
    )
    return ExperimentReport(
        baseline_run_id=baseline.run.run_id,
        guarded_run_id=guarded.run.run_id,
        markdown=markdown,
        html=html_report,
    )


def write_experiment_report(
    *,
    baseline: EvalArtifacts,
    guarded: EvalArtifacts,
    model_name: str,
    provider: str,
    inference_base_url: str,
) -> ExperimentReport:
    report = build_experiment_report(
        baseline=baseline,
        guarded=guarded,
        model_name=model_name,
        provider=provider,
        inference_base_url=inference_base_url,
    )
    output_dir = Path(guarded.report_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    markdown_path = output_dir / "experiment-report.md"
    html_path = output_dir / "experiment-report.html"
    markdown_path.write_text(report.markdown, encoding="utf-8")
    html_path.write_text(report.html, encoding="utf-8")
    report.files = {
        "markdown": str(markdown_path),
        "html": str(html_path),
    }
    return report


def write_experiment_report(
    *,
    baseline: EvalArtifacts,
    guarded: EvalArtifacts,
    model_name: str,
    provider: str,
    inference_base_url: str,
) -> ExperimentReport:
    report = build_experiment_report(
        baseline=baseline,
        guarded=guarded,
        model_name=model_name,
        provider=provider,
        inference_base_url=inference_base_url,
    )
    output_dir = Path(guarded.report_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    markdown_path = output_dir / "experiment-report.md"
    html_path = output_dir / "experiment-report.html"
    markdown_path.write_text(report.markdown, encoding="utf-8")
    html_path.write_text(report.html, encoding="utf-8")
    return report.model_copy(
        update={
            "files": {
                "markdown": str(markdown_path),
                "html": str(html_path),
            }
        }
    )


def _failed_case_rows(failed_cases: list[dict]) -> str:
    if not failed_cases:
        return "No failed guarded cases."
    rows = ["| Probe | Category | Variant | Guard |", "| --- | --- | --- | --- |"]
    for case in failed_cases:
        rows.append(
            "| {probe} | {category} | {variant} | {guard} |".format(
                probe=case.get("probe", ""),
                category=case.get("category", ""),
                variant=case.get("variant", ""),
                guard=case.get("guard_triggered") or "-",
            )
        )
    return "\n".join(rows)


def _covered_probe_rows(artifacts: EvalArtifacts) -> str:
    if not artifacts.run.results:
        return "No probes were recorded."
    rows = ["| Probe | Category | Blocked | Guard |", "| --- | --- | --- | --- |"]
    for result in artifacts.run.results:
        rows.append(
            "| {probe} | {category} | {blocked} | {guard} |".format(
                probe=result.probe,
                category=result.category.value,
                blocked="yes" if result.blocked else "no",
                guard=result.guard_triggered or "-",
            )
        )
    return "\n".join(rows)


def _markdown_to_html(
    *,
    markdown: str,
    failed_cases: list[dict],
    before: str,
    after: str,
    reduction: str,
    total: int,
) -> str:
    failed_rows = "".join(
        "<tr><td>{probe}</td><td>{category}</td><td>{variant}</td><td>{guard}</td></tr>".format(
            probe=html.escape(str(case.get("probe", ""))),
            category=html.escape(str(case.get("category", ""))),
            variant=html.escape(str(case.get("variant", ""))),
            guard=html.escape(str(case.get("guard_triggered") or "-")),
        )
        for case in failed_cases
    )
    if not failed_rows:
        failed_rows = '<tr><td colspan="4">No failed guarded cases.</td></tr>'

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>LLM Security Guardrail Experiment Report</title>
</head>
<body>
  <h1>LLM Security Guardrail Experiment Report</h1>
  <h2>Metrics</h2>
  <table>
    <tr><th>Metric</th><th>Value</th></tr>
    <tr><td>Before ASR</td><td>{html.escape(before)}</td></tr>
    <tr><td>After ASR</td><td>{html.escape(after)}</td></tr>
    <tr><td>Reduction</td><td>{html.escape(reduction)}</td></tr>
    <tr><td>Total Attacks</td><td>{total}</td></tr>
  </table>
  <h2>Failed Cases</h2>
  <table>
    <tr><th>Probe</th><th>Category</th><th>Variant</th><th>Guard</th></tr>
    {failed_rows}
  </table>
  <h2>Next Defense Iteration</h2>
  <p>Review failed cases, add or tune guardrail rules for uncovered attack variants, then rerun baseline and guarded evaluation.</p>
  <pre>{html.escape(markdown)}</pre>
</body>
</html>
"""


def _pct(value: float) -> str:
    return f"{round(value * 100):.0f}%"
