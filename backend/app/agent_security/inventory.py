"""Metadata-only Agent CLI inventory and enrolled-device upload."""

from __future__ import annotations

import json
import os
import getpass
import re
import shutil
import socket
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .models import AssetCarrier, AssetKind, AssetRecord, AssetState, ScanReport
from .assessment import provenance_for_path
from .asset_identity import normalized_content_hash
from .scanner import sha256_path
from .transport import validate_device_upload_url

_AGENT_COMMANDS = (
    ("claude-code", "Claude Code", "claude"),
    ("codex", "Codex CLI", "codex"),
    ("gemini-cli", "Gemini CLI", "gemini"),
    ("hermes", "Hermes Agent", "hermes"),
    ("openclaw", "OpenClaw", "openclaw"),
    ("opencode", "OpenCode", "opencode"),
    ("aider", "Aider", "aider"),
    ("qwen", "Qwen Code", "qwen"),
    ("stepcode", "Step Code", "step"),
)
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _version(command_path: str) -> str:
    try:
        result = subprocess.run(
            [command_path, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    output = result.stdout or result.stderr
    if result.returncode != 0 or not output.strip():
        return ""
    return _ANSI_RE.sub("", output.strip().splitlines()[0])[:120]


def discover_agent_assets(*, host: str = "") -> list[AssetRecord]:
    """Discover known Agent CLIs without reading their configs or credentials."""
    hostname = host or os.environ.get("AGENTSEC_HOST") or socket.gethostname()
    owner = os.environ.get("AGENTSEC_OWNER") or getpass.getuser()
    rows: list[AssetRecord] = []
    for key, display_name, command in _AGENT_COMMANDS:
        executable = shutil.which(command)
        if not executable:
            continue
        path = Path(executable).resolve()
        try:
            digest = sha256_path(path)
        except OSError:
            digest = ""
        rows.append(AssetRecord(
            asset_id=f"agent-{hostname}-{key}",
            kind=AssetKind.AGENT,
            name=display_name,
            version=_version(executable),
            path=str(path),
            sha256=digest,
            host=hostname,
            owner=owner,
            source="agentsec-inventory",
            provenance=provenance_for_path(str(path)),
            product=key,
            carrier=AssetCarrier.USER_INSTALLED,
            state=AssetState.INSTALLED,
            content_hash=normalized_content_hash(path),
            registered=False,
        ))
    return rows


def upload_agent_assets(*, url: str, device_key: str,
                        assets: list[AssetRecord],
                        scans: list[ScanReport] | None = None) -> dict[str, Any]:
    """Upload metadata to the central AgentSec endpoint using an enrolled token."""
    if not url:
        raise ValueError("inventory upload URL is required")
    if not device_key:
        raise ValueError("AGENTSEC_DEVICE_KEY is required for inventory upload")
    validate_device_upload_url(url)
    scans = scans or []
    if not assets and not scans:
        return {"accepted": 0, "device_id": ""}
    total = {"accepted": 0, "assets_accepted": 0, "scans_accepted": 0,
             "device_id": "", "hostname": ""}
    asset_batches = [assets[i:i + 1000] for i in range(0, len(assets), 1000)]
    scan_batches = [scans[i:i + 100] for i in range(0, len(scans), 100)]
    batch_count = max(len(asset_batches), len(scan_batches), 1)
    for index in range(batch_count):
        body = json.dumps(
            {
                "assets": [asset.model_dump(mode="json")
                           for asset in (asset_batches[index]
                                         if index < len(asset_batches) else [])],
                "scans": [sanitize_scan_report(report).model_dump(mode="json")
                          for report in (scan_batches[index]
                                         if index < len(scan_batches) else [])],
            },
            ensure_ascii=False,
        ).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "X-AgentSec-Device-Key": device_key,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                payload = json.loads(response.read().decode("utf-8") or "{}")
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"inventory upload failed with HTTP {exc.code}") from None
        except (urllib.error.URLError, OSError, TimeoutError):
            raise RuntimeError("inventory upload failed: central endpoint unavailable") from None
        if isinstance(payload, dict):
            for key in ("accepted", "assets_accepted", "scans_accepted"):
                total[key] += int(payload.get(key, 0))
            total["device_id"] = str(payload.get("device_id", total["device_id"]))
            total["hostname"] = str(payload.get("hostname", total["hostname"]))
    return total


def sanitize_scan_report(report: ScanReport) -> ScanReport:
    """Keep rule metadata while removing source snippets before persistence/upload."""
    return report.model_copy(update={
        "findings": [finding.model_copy(update={"evidence": ""})
                     for finding in report.findings],
    })
