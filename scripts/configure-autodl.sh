#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BACKEND_ENV="${PROJECT_ROOT}/backend/.env"
SERVICE_NAME="${LLMSEC_SYSTEMD_SERVICE:-llmsec-backend}"

APPLY=0
BASE_URL="${LLMSEC_OPENAI_BASE_URL:-}"
API_KEY="${LLMSEC_OPENAI_API_KEY:-}"
MODEL="${LLMSEC_OPENAI_MODEL:-qwen3:8b}"

usage() {
  cat <<'USAGE'
Usage:
  scripts/configure-autodl.sh --base-url URL --api-key KEY [--model MODEL] [--apply]

Default mode is dry-run. Add --apply to update backend/.env and restart llmsec-backend.

Examples:
  scripts/configure-autodl.sh --base-url http://127.0.0.1:18000/v1 --api-key sk-local
  scripts/configure-autodl.sh --base-url http://<autodl-host>:<port>/v1 --api-key <key> --apply
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply)
      APPLY=1
      shift
      ;;
    --base-url)
      BASE_URL="${2:-}"
      shift 2
      ;;
    --api-key)
      API_KEY="${2:-}"
      shift 2
      ;;
    --model)
      MODEL="${2:-}"
      shift 2
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

if [[ -z "${BASE_URL}" || -z "${API_KEY}" || -z "${MODEL}" ]]; then
  echo "Missing required AutoDL configuration." >&2
  usage >&2
  exit 2
fi

if [[ ! -f "${BACKEND_ENV}" ]]; then
  echo "Missing backend env file: ${BACKEND_ENV}" >&2
  exit 1
fi

echo "AutoDL configuration preview:"
echo "  LLMSEC_MODEL_PROVIDER=autodl"
echo "  LLMSEC_OPENAI_BASE_URL=${BASE_URL}"
echo "  LLMSEC_OPENAI_API_KEY=<redacted>"
echo "  LLMSEC_OPENAI_MODEL=${MODEL}"
echo "  env file: ${BACKEND_ENV}"
echo "  service: ${SERVICE_NAME}"

if [[ "${APPLY}" -ne 1 ]]; then
  echo
  echo "Dry-run only. Re-run with --apply to write backend/.env and restart the service."
  exit 0
fi

BACKUP="${BACKEND_ENV}.bak.$(date +%Y%m%d-%H%M%S)"
cp "${BACKEND_ENV}" "${BACKUP}"

BACKEND_ENV="${BACKEND_ENV}" \
AUTODL_BASE_URL="${BASE_URL}" \
AUTODL_API_KEY="${API_KEY}" \
AUTODL_MODEL="${MODEL}" \
python3 - <<'PY'
from pathlib import Path
import os

env_path = Path(os.environ["BACKEND_ENV"])
updates = {
    "LLMSEC_MODEL_PROVIDER": "autodl",
    "LLMSEC_OPENAI_BASE_URL": os.environ["AUTODL_BASE_URL"],
    "LLMSEC_OPENAI_API_KEY": os.environ["AUTODL_API_KEY"],
    "LLMSEC_OPENAI_MODEL": os.environ["AUTODL_MODEL"],
}

lines = env_path.read_text().splitlines()
seen: set[str] = set()
next_lines: list[str] = []
for line in lines:
    key = line.split("=", 1)[0] if "=" in line else ""
    if key in updates:
        next_lines.append(f"{key}={updates[key]}")
        seen.add(key)
    else:
        next_lines.append(line)

for key, value in updates.items():
    if key not in seen:
        next_lines.append(f"{key}={value}")

env_path.write_text("\n".join(next_lines) + "\n")
PY

if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files "${SERVICE_NAME}.service" >/dev/null 2>&1; then
  systemctl restart "${SERVICE_NAME}"
fi

echo "Updated ${BACKEND_ENV}; backup saved at ${BACKUP}"
echo "Run these checks next:"
echo "  curl -fsS http://127.0.0.1:8000/health"
echo "  curl -fsS -X POST http://127.0.0.1:8000/chat -H 'Content-Type: application/json' -d '{\"message\":\"hello\",\"guard_mode\":\"audit\"}'"
