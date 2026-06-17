from fastapi.testclient import TestClient

from app.api.main import create_app


def test_root_serves_built_frontend() -> None:
    client = TestClient(create_app())

    response = client.get("/")

    assert response.status_code == 200
    assert "LLM Security Guardrail Platform" in response.text
    assert "text/html" in response.headers["content-type"]
