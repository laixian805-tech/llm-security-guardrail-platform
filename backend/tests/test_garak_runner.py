import json
import subprocess

import pytest

from app.evals.garak import GarakEvalRunner
from app.guardrails.pipeline import GuardMode


def test_garak_runner_normalizes_report_artifacts(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    run_dir = tmp_path / "garak-test"

    def fake_run(command, cwd, env, capture_output, text, check, timeout):  # type: ignore[no-untyped-def]
        assert command[0] == "python-test"
        assert "--target_type" in command
        assert "openai.OpenAICompatible" in command
        assert timeout == 900
        assert env["OPENAICOMPATIBLE_API_KEY"] == "dummy"
        config_path = run_dir / "garak-config.json"
        config_payload = json.loads(config_path.read_text(encoding="utf-8"))
        extra_body = config_payload["plugins"]["generators"]["openai"]["OpenAICompatible"]["extra_params"]["extra_body"]
        assert extra_body["guard_mode"] == "audit"

        (run_dir / "garak.report.jsonl").write_text(
            "\n".join(
                [
                    json.dumps(
                        {
                            "entry_type": "eval",
                            "probe": "probes.promptinject.PromptInject",
                            "detector": "detectors.base.Trigger",
                            "passed": 1,
                            "total_evaluated": 1,
                        }
                    ),
                    json.dumps(
                        {
                            "entry_type": "eval",
                            "probe": "probes.dan.DanInTheWild",
                            "detector": "detectors.base.Trigger",
                            "passed": 0,
                            "total_evaluated": 1,
                        }
                    ),
                ]
            ),
            encoding="utf-8",
        )
        (run_dir / "garak.report.html").write_text("<html>ok</html>", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "garak ok", "")

    monkeypatch.setattr("app.evals.garak.importlib.util.find_spec", lambda _: object())
    monkeypatch.setattr("app.evals.garak.subprocess.run", fake_run)

    runner = GarakEvalRunner(
        reports_dir=tmp_path,
        service_base_url="http://127.0.0.1:8000",
        model_name="local-agent",
        python_executable="python-test",
    )

    artifacts = runner.run_with_artifacts(
        probes=["injection", "jailbreak"],
        guard_mode=GuardMode.AUDIT,
        run_id="garak-test",
    )

    assert artifacts.run.adapter == "garak"
    assert artifacts.run.summary is not None
    assert artifacts.run.summary.total_attacks == 2
    assert artifacts.run.summary.blocked == 1
    assert artifacts.run.results[0].probe == "promptinject.PromptInject"
    assert artifacts.run.results[0].category == "injection"
    assert artifacts.run.results[1].category == "jailbreak"
    assert artifacts.files["json"].endswith("results.json")
    assert artifacts.files["jsonl"].endswith("garak.report.jsonl")
    assert (run_dir / "results.json").exists()


def test_garak_runner_requires_installed_package(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.evals.garak.importlib.util.find_spec", lambda _: None)

    runner = GarakEvalRunner(
        reports_dir=tmp_path,
        service_base_url="http://127.0.0.1:8000",
        model_name="local-agent",
    )

    with pytest.raises(RuntimeError, match="Garak is not installed"):
        runner.run_with_artifacts(probes=["injection"], guard_mode=GuardMode.ENFORCE)


def test_garak_runner_maps_platform_probe_names(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    run_dir = tmp_path / "garak-platform-probes"
    captured = {}

    def fake_run(command, cwd, env, capture_output, text, check, timeout):  # type: ignore[no-untyped-def]
        probe_arg_index = command.index("--probes") + 1
        captured["probe_spec"] = command[probe_arg_index]
        (run_dir / "garak.report.jsonl").write_text(
            json.dumps(
                {
                    "entry_type": "eval",
                    "probe": "probes.promptinject.PromptInject",
                    "detector": "detectors.base.Trigger",
                    "passed": 1,
                    "total_evaluated": 1,
                }
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, "garak ok", "")

    monkeypatch.setattr("app.evals.garak.importlib.util.find_spec", lambda _: object())
    monkeypatch.setattr("app.evals.garak.subprocess.run", fake_run)

    runner = GarakEvalRunner(
        reports_dir=tmp_path,
        service_base_url="http://127.0.0.1:8000",
        model_name="local-agent",
        python_executable="python-test",
    )

    artifacts = runner.run_with_artifacts(
        probes=[
            "direct_injection",
            "role_takeover",
            "long_context_hijack",
            "rag_poisoning",
            "web_poisoning",
            "tool_return_poisoning",
            "unauthorized_tool_call",
        ],
        guard_mode=GuardMode.ENFORCE,
        run_id="garak-platform-probes",
    )

    assert captured["probe_spec"] == "promptinject,sysprompt_extraction,dan,latentinjection,web_injection"
    assert artifacts.run.probes == [
        "promptinject",
        "sysprompt_extraction",
        "dan",
        "latentinjection",
        "web_injection",
    ]


def test_garak_runner_reports_timeout(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(*args, **kwargs):  # type: ignore[no-untyped-def]
        assert kwargs["timeout"] == 12
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=12)

    monkeypatch.setattr("app.evals.garak.importlib.util.find_spec", lambda _: object())
    monkeypatch.setattr("app.evals.garak.subprocess.run", fake_run)

    runner = GarakEvalRunner(
        reports_dir=tmp_path,
        service_base_url="http://127.0.0.1:8000",
        model_name="local-agent",
        timeout_seconds=12,
    )

    with pytest.raises(RuntimeError, match="Garak run timed out after 12 seconds"):
        runner.run_with_artifacts(
            probes=["injection"],
            guard_mode=GuardMode.ENFORCE,
            run_id="garak-timeout",
        )


def test_garak_runner_includes_stdout_when_report_is_missing(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(*args, **kwargs):  # type: ignore[no-untyped-def]
        return subprocess.CompletedProcess(
            args[0],
            0,
            "Unknown probes: unsupported_probe",
            "",
        )

    monkeypatch.setattr("app.evals.garak.importlib.util.find_spec", lambda _: object())
    monkeypatch.setattr("app.evals.garak.subprocess.run", fake_run)

    runner = GarakEvalRunner(
        reports_dir=tmp_path,
        service_base_url="http://127.0.0.1:8000",
        model_name="local-agent",
    )

    with pytest.raises(RuntimeError, match="Unknown probes: unsupported_probe"):
        runner.run_with_artifacts(
            probes=["unsupported_probe"],
            guard_mode=GuardMode.ENFORCE,
            run_id="garak-missing-report",
        )
