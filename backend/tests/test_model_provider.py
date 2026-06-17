from app.models.provider import StubModelProvider


def test_stub_provider_returns_deterministic_response() -> None:
    provider = StubModelProvider(model_name="stub-security-model")

    response = provider.chat(
        messages=[
            {"role": "system", "content": "You are a safe assistant."},
            {"role": "user", "content": "Summarize the handbook."},
        ]
    )

    assert response.model == "stub-security-model"
    assert response.content == "Stub response: Summarize the handbook."
    assert response.latency_ms >= 0



def test_openai_compatible_provider_posts_chat_completion(monkeypatch) -> None:
    import httpx

    from app.models.provider import OpenAICompatibleModelProvider

    captured = {}

    def fake_post(url, json, headers, timeout):  # type: ignore[no-untyped-def]
        captured["url"] = url
        captured["json"] = json
        captured["headers"] = headers
        captured["timeout"] = timeout
        return httpx.Response(
            200,
            request=httpx.Request("POST", url),
            json={
                "model": "qwen3:8b",
                "choices": [
                    {"message": {"content": "remote ok"}}
                ],
            },
        )

    monkeypatch.setattr("app.models.provider.httpx.post", fake_post)
    provider = OpenAICompatibleModelProvider(
        base_url="https://autodl.example.com/v1",
        model_name="qwen3:8b",
        api_key="secret-token",
    )

    response = provider.chat([{"role": "user", "content": "hello"}])

    assert captured["url"] == "https://autodl.example.com/v1/chat/completions"
    assert captured["json"]["model"] == "qwen3:8b"
    assert captured["json"]["messages"] == [{"role": "user", "content": "hello"}]
    assert captured["headers"]["Authorization"] == "Bearer secret-token"
    assert response.content == "remote ok"
    assert response.model == "qwen3:8b"


def test_build_model_provider_accepts_autodl_alias() -> None:
    from app.api.main import build_model_provider
    from app.config.settings import Settings
    from app.models.provider import OpenAICompatibleModelProvider

    settings = Settings(
        model_provider="autodl",
        openai_base_url="https://autodl.example.com/v1",
        openai_api_key="secret-token",
        openai_model="qwen3:8b",
    )

    provider = build_model_provider(settings)

    assert isinstance(provider, OpenAICompatibleModelProvider)
