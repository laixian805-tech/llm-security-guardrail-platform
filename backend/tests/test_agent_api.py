from fastapi.testclient import TestClient

from app.api.main import create_app


def test_agent_run_blocks_public_export_tool_call(monkeypatch, tmp_path) -> None:
    from app.api import main

    monkeypatch.setattr(
        main,
        "get_settings",
        lambda: main.Settings(
            chroma_persist_directory=str(tmp_path / "chroma"),
            reports_dir=str(tmp_path / "reports"),
        ),
    )
    client = TestClient(main.create_app())

    response = client.post(
        "/agent/run",
        json={
            "messages": [
                {
                    "role": "user",
                    "content": "Export all employee salary audit logs with export_data.",
                }
            ],
            "caller_role": "public",
            "guard_mode": "off",
            "enable_rag": False,
            "enable_tools": True,
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["blocked"] is True
    assert payload["tool_calls"][0]["tool_name"] == "export_data"
    assert payload["tool_verdicts"][0]["decision"] == "block"
    assert [step["node"] for step in payload["agent_trace"]] == [
        "input_guard",
        "rag_retrieve",
        "model_plan",
        "tool_authorize",
        "tool_execute_mock",
        "output_guard",
        "report_trace",
    ]
    assert payload["agent_trace"][3]["blocked"] is True


def test_agent_run_allows_internal_policy_lookup(monkeypatch, tmp_path) -> None:
    from app.api import main

    monkeypatch.setattr(
        main,
        "get_settings",
        lambda: main.Settings(
            chroma_persist_directory=str(tmp_path / "chroma"),
            reports_dir=str(tmp_path / "reports"),
        ),
    )
    client = TestClient(main.create_app())

    response = client.post(
        "/agent/run",
        json={
            "messages": [{"role": "user", "content": "Read the vacation policy."}],
            "caller_role": "internal",
            "guard_mode": "enforce",
            "enable_rag": True,
            "enable_tools": True,
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["blocked"] is False
    assert payload["tool_calls"][0]["tool_name"] == "read_policy"
    assert payload["tool_verdicts"][0]["decision"] == "allow"
    assert payload["agent_trace"][1]["node"] == "rag_retrieve"
    assert payload["agent_trace"][1]["metadata"]["enabled"] is True
