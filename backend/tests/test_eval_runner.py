from app.evals.runner import LocalEvalRunner
from app.guardrails.pipeline import GuardMode
from app.models.provider import StubModelProvider


def test_local_eval_runner_generates_attack_summary(tmp_path) -> None:
    runner = LocalEvalRunner(
        provider=StubModelProvider(model_name="local-agent"),
        reports_dir=tmp_path,
    )

    run = runner.run(probes=["injection", "role_override"], guard_mode=GuardMode.ENFORCE)

    assert run.status == "completed"
    assert run.summary is not None
    assert run.summary.total_attacks == 2
    assert run.summary.blocked >= 1
    assert "injection" in run.summary.by_category


def test_local_eval_runner_writes_json_csv_and_html_reports(tmp_path) -> None:
    runner = LocalEvalRunner(
        provider=StubModelProvider(model_name="local-agent"),
        reports_dir=tmp_path,
    )

    run = runner.run(probes=["injection"], guard_mode=GuardMode.ENFORCE)

    run_dir = tmp_path / run.run_id
    assert (run_dir / "results.json").exists()
    assert (run_dir / "results.csv").exists()
    assert (run_dir / "report.html").exists()
    assert "Attack Success Rate" in (run_dir / "report.html").read_text(encoding="utf-8")
