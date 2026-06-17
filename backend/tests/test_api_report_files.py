from fastapi.testclient import TestClient

from app.api.main import create_app


def test_report_file_api_serves_html_and_json(monkeypatch, tmp_path) -> None:
    reports_dir = tmp_path / "reports"
    run_dir = reports_dir / "eval-file-test"
    run_dir.mkdir(parents=True)
    (run_dir / "report.html").write_text("<html><body>report ok</body></html>", encoding="utf-8")
    (run_dir / "results.json").write_text(
        """
        {
          "run_id": "eval-file-test",
          "adapter": "local",
          "guard_mode": "on",
          "probes": ["direct_injection"],
          "status": "completed",
          "results": []
        }
        """,
        encoding="utf-8",
    )

    from app.api import main

    monkeypatch.setattr(main, "get_settings", lambda: main.Settings(reports_dir=str(reports_dir)))
    client = TestClient(main.create_app())

    html_response = client.get("/report-files/eval-file-test/html")
    json_response = client.get("/report-files/eval-file-test/json")

    assert html_response.status_code == 200
    assert "text/html" in html_response.headers["content-type"]
    assert html_response.headers["content-disposition"].startswith("inline;")
    assert "report ok" in html_response.text
    assert json_response.status_code == 200
    assert "application/json" in json_response.headers["content-type"]
    assert json_response.json()["run_id"] == "eval-file-test"


def test_report_file_api_rejects_unknown_file_key(monkeypatch, tmp_path) -> None:
    reports_dir = tmp_path / "reports"
    (reports_dir / "eval-file-test").mkdir(parents=True)

    from app.api import main

    monkeypatch.setattr(main, "get_settings", lambda: main.Settings(reports_dir=str(reports_dir)))
    client = TestClient(main.create_app())

    response = client.get("/report-files/eval-file-test/passwd")

    assert response.status_code == 404
