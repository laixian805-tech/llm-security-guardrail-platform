#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

BASE_URL="${LLMSEC_SERVICE_BASE_URL:-http://127.0.0.1:8000}"
REPORTS_DIR="${LLMSEC_REPORTS_DIR:-/root/llmsec-assets/reports}"
MODEL="${LLMSEC_OPENAI_MODEL:-qwen3:8b}"
INCLUDE_GARAK=0
GARAK_PROBE_SPEC="${LLMSEC_GARAK_PROBE_SPEC:-promptinject.HijackHateHumans}"
DRY_RUN=0

usage() {
  cat <<'USAGE'
Usage:
  scripts/run-real-security-cycle.sh [--base-url URL] [--reports-dir DIR] [--model MODEL] [--include-garak] [--garak-probe-spec SPEC] [--dry-run]

Default cycle:
  warmup /chat
  Promptfoo guard_mode=off
  Promptfoo guard_mode=audit
  Promptfoo guard_mode=enforce
  write cycle manifest

Garak is opt-in because promptinject probes can contain hundreds of model calls:
  scripts/run-real-security-cycle.sh --include-garak --garak-probe-spec promptinject.HijackHateHumans
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base-url)
      BASE_URL="${2:-}"
      shift 2
      ;;
    --reports-dir)
      REPORTS_DIR="${2:-}"
      shift 2
      ;;
    --model)
      MODEL="${2:-}"
      shift 2
      ;;
    --include-garak)
      INCLUDE_GARAK=1
      shift
      ;;
    --garak-probe-spec)
      GARAK_PROBE_SPEC="${2:-}"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "${BASE_URL}" || -z "${REPORTS_DIR}" || -z "${MODEL}" ]]; then
  echo "Missing required cycle configuration." >&2
  usage >&2
  exit 2
fi

export BASE_URL REPORTS_DIR MODEL INCLUDE_GARAK GARAK_PROBE_SPEC DRY_RUN PROJECT_ROOT

python3 - <<'PY'
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from urllib import request

base_url = os.environ["BASE_URL"].rstrip("/")
reports_dir = Path(os.environ["REPORTS_DIR"])
model = os.environ["MODEL"]
include_garak = os.environ["INCLUDE_GARAK"] == "1"
garak_probe_spec = os.environ["GARAK_PROBE_SPEC"]
dry_run = os.environ["DRY_RUN"] == "1"

cycle_id = "cycle-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
cycle_dir = reports_dir / cycle_id

steps: list[tuple[str, dict]] = [
    (
        "warmup-chat",
        {
            "method": "POST",
            "path": "/chat",
            "body": {"message": "Return exactly: warmup ok", "guard_mode": "audit"},
        },
    ),
    (
        "promptfoo-baseline-off",
        {
            "method": "POST",
            "path": "/eval/run",
            "body": {"adapter": "promptfoo", "probes": ["injection"], "guard_mode": "off", "model": model},
        },
    ),
    (
        "promptfoo-audit",
        {
            "method": "POST",
            "path": "/eval/run",
            "body": {"adapter": "promptfoo", "probes": ["injection"], "guard_mode": "audit", "model": model},
        },
    ),
    (
        "promptfoo-enforce",
        {
            "method": "POST",
            "path": "/eval/run",
            "body": {"adapter": "promptfoo", "probes": ["injection"], "guard_mode": "enforce", "model": model},
        },
    ),
]

if include_garak:
    steps.extend(
        [
            (
                "garak-baseline-off",
                {
                    "method": "POST",
                    "path": "/eval/run",
                    "body": {
                        "adapter": "garak",
                        "probes": ["injection"],
                        "guard_mode": "off",
                        "model": model,
                        "garak_probe_spec": garak_probe_spec,
                    },
                },
            ),
            (
                "garak-enforce",
                {
                    "method": "POST",
                    "path": "/eval/run",
                    "body": {
                        "adapter": "garak",
                        "probes": ["injection"],
                        "guard_mode": "enforce",
                        "model": model,
                        "garak_probe_spec": garak_probe_spec,
                    },
                },
            ),
        ]
    )

print(f"cycle_id={cycle_id}")
print(f"base_url={base_url}")
print(f"reports_dir={reports_dir}")
print(f"model={model}")
print(f"include_garak={include_garak}")
if include_garak:
    print(f"garak_probe_spec={garak_probe_spec}")

if dry_run:
    for name, step in steps:
        print(f"DRY-RUN {name}: {step['method']} {step['path']} {json.dumps(step['body'], ensure_ascii=False)}")
    raise SystemExit(0)

cycle_dir.mkdir(parents=True, exist_ok=True)

def call_json(path: str, body: dict, timeout: int = 1200) -> dict:
    data = json.dumps(body).encode("utf-8")
    req = request.Request(
        f"{base_url}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))

manifest: dict = {
    "cycle_id": cycle_id,
    "started_at": datetime.now(timezone.utc).isoformat(),
    "base_url": base_url,
    "model": model,
    "include_garak": include_garak,
    "garak_probe_spec": garak_probe_spec if include_garak else None,
    "steps": [],
}

for name, step in steps:
    print(f"running {name}")
    response = call_json(step["path"], step["body"])
    record = {"name": name, "request": step["body"], "response": response}
    run = response.get("run") or {}
    if run:
        summary = run.get("summary") or {}
        print(
            "  run_id={run_id} total={total} blocked={blocked} report_dir={report_dir}".format(
                run_id=run.get("run_id"),
                total=summary.get("total_attacks"),
                blocked=summary.get("blocked"),
                report_dir=response.get("report_dir"),
            )
        )
    else:
        print(f"  response keys={sorted(response)}")
    manifest["steps"].append(record)

manifest["finished_at"] = datetime.now(timezone.utc).isoformat()
manifest_path = cycle_dir / "cycle-manifest.json"
manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"manifest={manifest_path}")
PY
