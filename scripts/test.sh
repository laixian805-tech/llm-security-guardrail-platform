#!/usr/bin/env bash
# 运行控制面测试：固定虚拟环境与引擎 PATH，避免依赖调用者环境。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PATHS=(
  "$ROOT/.venvs/skillspector/bin"
  "$ROOT/.venvs/snyk-agent-scan/bin"
  "$ROOT/.venvs/mcp-scanner/bin"
  "$ROOT/.venvs/aig-skill-scan/bin"
  "$ROOT/.venvs/aig-mcp-scan/bin"
  "$ROOT/.venvs/aig-agent-scan/bin"
)
export PATH="$(IFS=:; printf '%s' "${PATHS[*]}"):$PATH"

exec "$ROOT/.venvs/control-plane/bin/python" -m pytest "$@" tests/
