from fastapi.testclient import TestClient

from app.api.main import create_app
from app.evals.runner import EvalArtifacts
from app.schemas.security import AttackCategory, AttackResult, EvalRun, EvalStatus


def test_eval_run_api_generates_report_artifacts() -> None:
    client = TestClient(create_app())

    response = client.post(
        "/eval/run",
        json={"probes": ["injection", "role_override"], "guard_mode": "enforce"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["run"]["status"] == "completed"
    assert payload["run"]["summary"]["total_attacks"] == 2
    assert payload["files"]["json"].endswith("results.json")
    assert payload["files"]["csv"].endswith("results.csv")
    assert payload["files"]["html"].endswith("report.html")


def test_reports_api_returns_generated_eval_run() -> None:
    client = TestClient(create_app())
    create_response = client.post(
        "/eval/run",
        json={"probes": ["injection"], "guard_mode": "enforce"},
    )
    run_id = create_response.json()["run"]["run_id"]

    report_response = client.get(f"/reports/{run_id}")

    assert report_response.status_code == 200
    payload = report_response.json()
    assert payload["run"]["run_id"] == run_id
    assert payload["run"]["summary"]["total_attacks"] == 1


def test_reports_api_returns_404_for_unknown_run() -> None:
    client = TestClient(create_app())

    response = client.get("/reports/missing-run")

    assert response.status_code == 404


def test_eval_run_api_supports_garak_adapter(monkeypatch) -> None:
    class FakeGarakRunner:
        def __init__(self, **kwargs) -> None:
            self.kwargs = kwargs

        def run_with_artifacts(
            self,
            *,
            probes,
            guard_mode,
            guard_engine,
            garak_probe_spec,
            garak_detector_spec,
        ):
            assert guard_engine.value == "nemo"
            run = EvalRun(
                run_id="garak-test",
                adapter="garak",
                guard_mode="on",
                probes=["promptinject"],
                status=EvalStatus.COMPLETED,
                results=[
                    AttackResult(
                        run_id="garak-test",
                        probe="promptinject.PromptInject",
                        category=AttackCategory.INJECTION,
                        variant="PromptInject",
                        prompt="probe",
                        response="summary",
                        blocked=True,
                        confidence=1.0,
                        latency_ms=0,
                    )
                ],
            )
            return EvalArtifacts(
                run=run,
                report_dir="/tmp/garak-test",
                files={
                    "json": "/tmp/garak-test/results.json",
                    "html": "/tmp/garak-test/garak.report.html",
                },
            )

    from app.api import main

    monkeypatch.setattr(main, "GarakEvalRunner", FakeGarakRunner)
    client = TestClient(main.create_app())

    response = client.post(
        "/eval/run",
        json={"adapter": "garak", "probes": ["injection"], "guard_mode": "enforce"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["run"]["adapter"] == "garak"
    assert payload["run"]["summary"]["total_attacks"] == 1


def test_eval_run_api_returns_400_for_runner_error(monkeypatch) -> None:
    class FailingGarakRunner:
        def __init__(self, **kwargs) -> None:
            self.kwargs = kwargs

        def run_with_artifacts(
            self,
            *,
            probes,
            guard_mode,
            guard_engine,
            garak_probe_spec,
            garak_detector_spec,
        ):
            assert guard_engine.value == "nemo"
            raise RuntimeError("Unknown probes: unsupported_probe")

    from app.api import main

    monkeypatch.setattr(main, "GarakEvalRunner", FailingGarakRunner)
    client = TestClient(main.create_app())

    response = client.post(
        "/eval/run",
        json={"adapter": "garak", "probes": ["unsupported_probe"], "guard_mode": "enforce"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Unknown probes: unsupported_probe"


def test_eval_run_api_supports_promptfoo_adapter(monkeypatch) -> None:
    class FakePromptfooRunner:
        def __init__(self, **kwargs) -> None:
            self.kwargs = kwargs

        def run_with_artifacts(self, *, probes, guard_mode, guard_engine):
            assert guard_engine.value == "nemo"
            run = EvalRun(
                run_id="promptfoo-test",
                adapter="promptfoo",
                guard_mode="on",
                probes=["injection"],
                status=EvalStatus.COMPLETED,
                results=[
                    AttackResult(
                        run_id="promptfoo-test",
                        probe="injection",
                        category=AttackCategory.INJECTION,
                        variant="ignore_previous",
                        prompt="probe",
                        response="I cannot comply with that request.",
                        blocked=True,
                        confidence=0.0,
                        latency_ms=0,
                    )
                ],
            )
            return EvalArtifacts(
                run=run,
                report_dir="/tmp/promptfoo-test",
                files={"json": "/tmp/promptfoo-test/results.json", "promptfoo": "/tmp/promptfoo-test/promptfoo-results.json"},
            )

    from app.api import main

    monkeypatch.setattr(main, "PromptfooEvalRunner", FakePromptfooRunner)
    client = TestClient(main.create_app())

    response = client.post(
        "/eval/run",
        json={"adapter": "promptfoo", "probes": ["injection"], "guard_mode": "enforce"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["run"]["adapter"] == "promptfoo"
    assert payload["run"]["summary"]["total_attacks"] == 1
