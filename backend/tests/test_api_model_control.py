from fastapi.testclient import TestClient


def test_autodl_model_status_lists_supported_and_available_models(monkeypatch, tmp_path) -> None:
    from app.api import main

    monkeypatch.setattr(
        main,
        "get_settings",
        lambda: main.Settings(
            model_provider="autodl",
            openai_model="qwen3:8b",
            openai_base_url="http://127.0.0.1:18000/v1",
            chroma_persist_directory=str(tmp_path / "chroma"),
            reports_dir=str(tmp_path / "reports"),
        ),
    )
    monkeypatch.setattr(main, "available_model_names", lambda settings: {"qwen3:8b"})
    client = TestClient(main.create_app())

    response = client.get("/models/autodl-status")

    assert response.status_code == 200
    payload = response.json()
    assert payload["active_model"] == "qwen3:8b"
    assert payload["available_models"] == ["qwen3:8b"]
    assert payload["supported_models"] == ["qwen3:8b", "mistral-7b"]
    assert payload["switchable"] is True


def test_autodl_model_status_prefers_online_model_after_backend_restart(monkeypatch, tmp_path) -> None:
    from app.api import main

    monkeypatch.setattr(
        main,
        "get_settings",
        lambda: main.Settings(
            model_provider="autodl",
            openai_model="qwen3:8b",
            openai_base_url="http://127.0.0.1:18000/v1",
            chroma_persist_directory=str(tmp_path / "chroma"),
            reports_dir=str(tmp_path / "reports"),
        ),
    )
    monkeypatch.setattr(main, "available_model_names", lambda settings: {"mistral-7b"})
    client = TestClient(main.create_app())

    response = client.get("/models/autodl-status")

    assert response.status_code == 200
    payload = response.json()
    assert payload["active_model"] == "mistral-7b"
    assert payload["available_models"] == ["mistral-7b"]


def test_switch_autodl_model_updates_runtime_health(monkeypatch, tmp_path) -> None:
    from app.api import main

    commands = []

    monkeypatch.setattr(
        main,
        "get_settings",
        lambda: main.Settings(
            model_provider="autodl",
            openai_model="qwen3:8b",
            openai_base_url="http://127.0.0.1:18000/v1",
            chroma_persist_directory=str(tmp_path / "chroma"),
            reports_dir=str(tmp_path / "reports"),
        ),
    )
    monkeypatch.setattr(main, "run_model_manager", lambda action, model: commands.append((action, model)) or f"{action}:{model}")
    monkeypatch.setattr(main, "wait_for_model_available", lambda settings, model, timeout_seconds=180: True)
    client = TestClient(main.create_app())

    response = client.post("/models/switch", json={"model": "mistral-7b"})

    assert response.status_code == 200
    payload = response.json()
    assert payload["previous_model"] == "qwen3:8b"
    assert payload["active_model"] == "mistral-7b"
    assert payload["status"] == "ready"
    assert commands == [("stop", "qwen3:8b"), ("start", "mistral-7b")]
    assert client.get("/health").json()["model_name"] == "mistral-7b"


def test_switch_autodl_model_rejects_unknown_model(monkeypatch, tmp_path) -> None:
    from app.api import main

    monkeypatch.setattr(
        main,
        "get_settings",
        lambda: main.Settings(
            model_provider="autodl",
            openai_model="qwen3:8b",
            chroma_persist_directory=str(tmp_path / "chroma"),
            reports_dir=str(tmp_path / "reports"),
        ),
    )
    client = TestClient(main.create_app())

    response = client.post("/models/switch", json={"model": "llama-70b"})

    assert response.status_code == 400
    assert "Unsupported model" in response.json()["detail"]
