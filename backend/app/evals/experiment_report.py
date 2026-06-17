from __future__ import annotations

import html
from pathlib import Path

from pydantic import BaseModel, Field

from app.evals.defense_feedback import DefenseFeedbackResponse
from app.evals.paired import compare_artifacts
from app.evals.runner import EvalArtifacts


class ExperimentReport(BaseModel):
    baseline_run_id: str = ""
    guarded_run_id: str = ""
    markdown: str
    html: str
    files: dict[str, str] = Field(default_factory=dict)


def build_experiment_report(
    *,
    baseline: EvalArtifacts,
    guarded: EvalArtifacts,
    model_name: str,
    provider: str,
    inference_base_url: str,
    defense_feedback: DefenseFeedbackResponse | None = None,
) -> ExperimentReport:
    comparison = compare_artifacts(baseline=baseline, guarded=guarded)
    before = _pct(comparison.before_asr)
    after = _pct(comparison.after_asr)
    reduction = _pct(comparison.reduction_pct / 100)
    failed_rows = _failed_case_rows(comparison.failed_cases)
    covered_rows = _covered_probe_rows(guarded)
    feedback_markdown = _defense_feedback_markdown(defense_feedback)
    conclusion = (
        "接入护栏前，Agent 会在 RAG 投毒、角色接管、工具返回投毒场景下执行不安全行为；"
        "接入护栏后，系统通过来源分级、语义检测、策略隔离和工具权限校验阻断攻击链路。"
    )

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

## Core Conclusion

{conclusion}

## Failed Cases

{failed_rows}

## Covered Probes

{covered_rows}

## Defense Feedback

{feedback_markdown}

## Next Defense Iteration

Review failed cases, convert them into regression payloads, tune the highest-priority guardrail area, and rerun the same baseline/guarded experiment.
"""

    html_report = _markdown_to_html(
        markdown=markdown,
        failed_cases=comparison.failed_cases,
        before=before,
        after=after,
        reduction=reduction,
        total=comparison.total_attacks,
        conclusion=conclusion,
        defense_feedback=defense_feedback,
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
    defense_feedback: DefenseFeedbackResponse | None = None,
) -> ExperimentReport:
    report = build_experiment_report(
        baseline=baseline,
        guarded=guarded,
        model_name=model_name,
        provider=provider,
        inference_base_url=inference_base_url,
        defense_feedback=defense_feedback,
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
                "experiment_markdown": str(markdown_path),
                "experiment_html": str(html_path),
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


def _defense_feedback_markdown(defense_feedback: DefenseFeedbackResponse | None) -> str:
    if defense_feedback is None:
        return "Defense feedback was not generated for this run."

    lines = [
        f"- Failed Samples: {defense_feedback.total_failed}",
        f"- Feedback JSON: {defense_feedback.files.get('json', 'not written')}",
        f"- Next Round Payloads: {defense_feedback.files.get('next_payloads', 'not written')}",
        "",
        "### Top Suggestions",
        "",
    ]
    for suggestion in defense_feedback.suggestions[:4]:
        lines.append(
            f"- `{suggestion.failure_type}` -> {suggestion.rule_area}: {suggestion.new_rule_suggestions[0]}"
        )
    lines.extend(["", "### Next Round Payloads", ""])
    for payload in defense_feedback.next_round_payloads[:6]:
        lines.append(f"- [{payload.get('failure_type', 'unknown')}] {payload.get('payload', '')}")
    return "\n".join(lines)


def _markdown_to_html(
    *,
    markdown: str,
    failed_cases: list[dict],
    before: str,
    after: str,
    reduction: str,
    total: int,
    conclusion: str,
    defense_feedback: DefenseFeedbackResponse | None,
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

    feedback_rows = ""
    if defense_feedback:
        feedback_rows = "".join(
            "<li><strong>{failure_type}</strong> · {rule_area} · {suggestion}</li>".format(
                failure_type=html.escape(suggestion.failure_type),
                rule_area=html.escape(suggestion.rule_area),
                suggestion=html.escape(suggestion.new_rule_suggestions[0]),
            )
            for suggestion in defense_feedback.suggestions[:4]
        )
    if not feedback_rows:
        feedback_rows = "<li>Defense feedback was not generated for this run.</li>"

    payload_rows = ""
    if defense_feedback:
        payload_rows = "".join(
            "<li>[{failure_type}] {payload}</li>".format(
                failure_type=html.escape(str(payload.get("failure_type", "unknown"))),
                payload=html.escape(str(payload.get("payload", ""))),
            )
            for payload in defense_feedback.next_round_payloads[:6]
        )
    if not payload_rows:
        payload_rows = "<li>No next-round payloads were generated.</li>"

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
  <h2>Core Conclusion</h2>
  <p>{html.escape(conclusion)}</p>
  <h2>Failed Cases</h2>
  <table>
    <tr><th>Probe</th><th>Category</th><th>Variant</th><th>Guard</th></tr>
    {failed_rows}
  </table>
  <h2>Defense Feedback</h2>
  <ul>{feedback_rows}</ul>
  <h3>Next Round Payloads</h3>
  <ul>{payload_rows}</ul>
  <pre>{html.escape(markdown)}</pre>
</body>
</html>
"""


def _pct(value: float) -> str:
    return f"{round(value * 100):.0f}%"
