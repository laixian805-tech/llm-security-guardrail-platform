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
