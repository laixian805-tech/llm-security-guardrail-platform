from fastapi.testclient import TestClient

from app.api.main import create_app


def test_health_endpoint_returns_runtime_paths(monkeypatch) -> None:
    monkeypatch.setenv("LLMSEC_MODEL_PROVIDER", "stub")

    client = TestClient(create_app())

    response = client.get("/health")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["service"] == "llm-security-guardrail-platform"
    assert payload["assets_root"].endswith("llmsec-assets")
    assert payload["model_provider"] == "stub"
    assert payload["model_name"] == "qwen3:8b"
    assert payload["inference_base_url"] is None
    assert payload["local_inference"] is False
    assert payload["guard_engine"] == "nemo"
    assert payload["nemo_runtime_available"] is True
    assert payload["nemo_fallback_engine"] == "custom_nemo"
    assert "ollama_model" not in payload


def test_health_endpoint_reports_autodl_runtime(monkeypatch) -> None:
    monkeypatch.setenv("LLMSEC_MODEL_PROVIDER", "autodl")
    monkeypatch.setenv("LLMSEC_OPENAI_BASE_URL", "https://autodl.example.com/v1")
    monkeypatch.setenv("LLMSEC_OPENAI_MODEL", "qwen3:8b")

    client = TestClient(create_app())

    response = client.get("/health")

    assert response.status_code == 200
    payload = response.json()
    assert payload["model_provider"] == "autodl"
    assert payload["model_name"] == "qwen3:8b"
    assert payload["inference_base_url"] == "https://autodl.example.com/v1"
    assert payload["local_inference"] is False


def test_guardrails_status_reports_nemo_runtime(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("LLMSEC_MODEL_PROVIDER", "stub")
    monkeypatch.setenv("LLMSEC_ASSETS_ROOT", str(tmp_path / "assets"))

    client = TestClient(create_app())

    response = client.get("/guardrails/status")

    assert response.status_code == 200
    payload = response.json()
    assert payload["guard_engine"] == "nemo"
    assert payload["nemo_runtime_available"] is True
    assert payload["nemo_config_exists"] is True
    assert payload["nemo_config_loaded"] is True
    assert payload["nemo_fallback_engine"] == "custom_nemo"
    assert payload["active_guard_pack"] is False


def test_nemo_defense_pack_exposes_rails_prompts_and_blocked_intents(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("LLMSEC_MODEL_PROVIDER", "stub")
    monkeypatch.setenv("LLMSEC_ASSETS_ROOT", str(tmp_path / "assets"))

    client = TestClient(create_app())

    response = client.get("/guardrails/nemo-pack")

    assert response.status_code == 200
    payload = response.json()
    assert payload["engine"] == "nemo"
    assert "llmsec deterministic input check" in payload["rails"]["input_flows"]
    assert "self_check_output" in {prompt["task"] for prompt in payload["prompts"]}
    assert {"prompt_injection", "tool_abuse", "rag_poisoning"}.issubset(
        {intent["intent"] for intent in payload["blocked_intents"]}
    )
    assert "ToolGateway" in payload["fallback_policy"]["deterministic_boundaries"]
