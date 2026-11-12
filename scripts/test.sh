#!/usr/bin/env bash
# 运行控制面测试：固定虚拟环境与引擎 PATH，避免依赖调用者环境。
#
# 先跑硬编码扫描再跑测试：扫描器几十毫秒就能报出"版本真值散开""常量没被引用"
# 这类问题，放在 pytest 前面可以在几十秒的测试之前就失败，省一轮等待。
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

echo "== 硬编码与重复真值扫描 =="
"$ROOT/.venvs/control-plane/bin/python" "$ROOT/scripts/lab/scan_hardcoded.py"

echo "== 控制面测试 =="
exec "$ROOT/.venvs/control-plane/bin/python" -m pytest "$@" tests/
