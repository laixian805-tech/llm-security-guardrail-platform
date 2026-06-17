from fastapi.testclient import TestClient


def test_guard_pack_preview_validates_candidate_without_activating(monkeypatch, tmp_path) -> None:
    from app.api import main

    monkeypatch.setattr(
        main,
        "get_settings",
        lambda: main.Settings(
            assets_root=str(tmp_path / "assets"),
            reports_dir=str(tmp_path / "reports"),
            chroma_persist_directory=str(tmp_path / "chroma"),
        ),
    )
    client = TestClient(main.create_app())

    response = client.post(
        "/guard-packs/preview",
        json={
            "schema_version": 1,
            "rule_templates": [
                {
                    "rule_name": "student_custom_rule",
                    "stage": "pre_input",
                    "pattern": r"\bforbidden-lab-token\b",
                    "reason": "Block the lab token.",
                    "source_failure_type": "direct_injection",
                }
            ],
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["valid"] is True
    assert payload["active"] is False
    assert payload["rule_count"] == 1
    assert not (tmp_path / "assets" / "guard-packs" / "active.json").exists()


def test_guard_pack_activate_affects_regression_preview_and_deactivate_removes_it(monkeypatch, tmp_path) -> None:
    from app.api import main

    monkeypatch.setattr(
        main,
        "get_settings",
        lambda: main.Settings(
            assets_root=str(tmp_path / "assets"),
            reports_dir=str(tmp_path / "reports"),
            chroma_persist_directory=str(tmp_path / "chroma"),
        ),
    )
    client = TestClient(main.create_app())
    guard_pack = {
        "schema_version": 1,
        "rule_templates": [
            {
                "rule_name": "student_custom_rule",
                "stage": "pre_input",
                "pattern": r"\bforbidden-lab-token\b",
                "reason": "Block the lab token.",
                "source_failure_type": "direct_injection",
            }
        ],
    }

    activate = client.post("/guard-packs/activate", json=guard_pack)
    assert activate.status_code == 200
    assert activate.json()["active"] is True

    preview = client.post(
        "/experiments/regression-preview",
        json={"payloads": [{"payload": "This contains forbidden-lab-token."}]},
    )
    assert preview.status_code == 200
    assert preview.json()["results"][0]["guard_triggered"] == "student_custom_rule"

    active = client.get("/guard-packs/active")
    assert active.status_code == 200
    assert active.json()["rule_count"] == 1

    deactivated = client.post("/guard-packs/deactivate")
    assert deactivated.status_code == 200
    assert deactivated.json()["active"] is False

    preview_after = client.post(
        "/experiments/regression-preview",
        json={"payloads": [{"payload": "This contains forbidden-lab-token."}]},
    )
    assert preview_after.status_code == 200
    assert preview_after.json()["results"][0]["blocked"] is False


def test_guard_pack_activate_rejects_invalid_regex(monkeypatch, tmp_path) -> None:
    from app.api import main

    monkeypatch.setattr(
        main,
        "get_settings",
        lambda: main.Settings(
            assets_root=str(tmp_path / "assets"),
            reports_dir=str(tmp_path / "reports"),
            chroma_persist_directory=str(tmp_path / "chroma"),
        ),
    )
    client = TestClient(main.create_app())

    response = client.post(
        "/guard-packs/activate",
        json={
            "rule_templates": [
                {
                    "rule_name": "broken_rule",
                    "stage": "pre_input",
                    "pattern": "(",
                    "reason": "Broken.",
                }
            ]
        },
    )

    assert response.status_code == 400
    assert "errors" in response.json()["detail"]
