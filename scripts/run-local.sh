#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -f "$ROOT/.env" ]]; then
  set -a
  source "$ROOT/.env"
  set +a
fi
PATHS=(
  "$ROOT/.venvs/skillspector/bin"
  "$ROOT/.venvs/snyk-agent-scan/bin"
  "$ROOT/.venvs/mcp-scanner/bin"
  "$ROOT/.venvs/aig-skill-scan/bin"
  "$ROOT/.venvs/aig-mcp-scan/bin"
  "$ROOT/.venvs/aig-agent-scan/bin"
)
export PATH="$(IFS=:; printf '%s' "${PATHS[*]}"):$PATH"
export FUSION_SCAN_ROOT="${FUSION_SCAN_ROOT:-$ROOT/workspace}"
export FUSION_BIND="${FUSION_BIND:-127.0.0.1}"
export PORT="${PORT:-8000}"
exec python3 "$ROOT/backend/server.py"
