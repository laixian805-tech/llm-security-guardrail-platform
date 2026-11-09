from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import json

from app.agent_security.models import AssetKind, AssetRecord, ScanFinding, ScanReport, ScanVerdict
from app.agent_security.inventory import upload_agent_assets

from app.agent_security.inventory import discover_agent_assets


def test_discovery_reports_only_present_agent_cli_metadata(
    tmp_path: Path, monkeypatch
) -> None:
    executable = tmp_path / "codex"
    executable.write_text("test executable", encoding="utf-8")

    def which(name: str) -> str | None:
        return str(executable) if name == "codex" else None

    monkeypatch.setattr("app.agent_security.inventory.shutil.which", which)
    monkeypatch.setattr(
        "app.agent_security.inventory.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout="codex-cli 0.test\n", stderr=""),
    )

    assets = discover_agent_assets(host="agentsec-lab")

    assert len(assets) == 1
    asset = assets[0]
    assert asset.asset_id == "agent-agentsec-lab-codex"
    assert asset.name == "Codex CLI"
    assert asset.version == "codex-cli 0.test"
    assert asset.host == "agentsec-lab"
    assert asset.sha256
    assert not asset.registered


def test_inventory_upload_batches_large_scan_inventory_and_strips_evidence(
    monkeypatch,
) -> None:
    requests = []

    class Response:
        def __init__(self, payload):
            self.payload = payload

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            body = json.loads(requests[-1].data)
            return json.dumps({
                "accepted": len(body["assets"]) + len(body["scans"]),
                "assets_accepted": len(body["assets"]),
                "scans_accepted": len(body["scans"]),
                "device_id": "lab-device",
                "hostname": "agentsec-test",
            }).encode()

    def fake_urlopen(request, timeout):
        requests.append(request)
        return Response({})

    monkeypatch.setattr("app.agent_security.inventory.urllib.request.urlopen", fake_urlopen)
    assets = [AssetRecord(asset_id="a1", kind=AssetKind.AGENT, name="Codex")]
    scans = [ScanReport(
        scan_id=f"scan-{index}", ts="2026-11-08T00:00:00+00:00", host="local",
        target_kind=AssetKind.SKILL, target_name=f"skill-{index}",
        target_path=f"/tmp/skill-{index}", sha256=f"{index:064x}",
        findings=[ScanFinding(rule_id="S01", name="hidden", severity="high",
                              action="alert", evidence="synthetic-secret-text")],
        verdict=ScanVerdict.ALERT,
    ) for index in range(205)]

    result = upload_agent_assets(
        url="https://inventory.example/api/agent-security/assets/inventory",
        device_key="test-device-token",
        assets=assets,
        scans=scans,
    )

    assert len(requests) == 3
    assert result == {
        "accepted": 206,
        "assets_accepted": 1,
        "scans_accepted": 205,
        "device_id": "lab-device",
        "hostname": "agentsec-test",
    }
    serialized = "".join(request.data.decode() for request in requests)
    assert "synthetic-secret-text" not in serialized
