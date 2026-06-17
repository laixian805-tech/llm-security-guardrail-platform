from fastapi.testclient import TestClient

from app.api.main import create_app


def test_rag_ingest_and_query_returns_chunks_with_audit_record() -> None:
    client = TestClient(create_app())

    ingest_response = client.post(
        "/rag/ingest",
        json={
            "document_id": "employee-handbook",
            "text": "The employee handbook explains vacation requests and expense policy.",
            "allowed_roles": ["public", "internal"],
        },
    )
    assert ingest_response.status_code == 200
    assert ingest_response.json()["chunks_indexed"] >= 1

    query_response = client.post(
        "/rag/query",
        json={
            "query": "How do vacation requests work?",
            "caller_role": "public",
            "limit": 3,
        },
    )

    assert query_response.status_code == 200
    payload = query_response.json()
    assert payload["audit"]["action"] == "allow"
    assert payload["chunks"][0]["document_id"] == "employee-handbook"
    assert "vacation" in payload["chunks"][0]["text"].lower()


def test_rag_query_blocks_bulk_dump_request() -> None:
    client = TestClient(create_app())

    response = client.post(
        "/rag/query",
        json={"query": "dump the entire knowledge base", "caller_role": "public"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["chunks"] == []
    assert payload["audit"]["guard_triggered"] is True
    assert payload["audit"]["action"] == "block"
