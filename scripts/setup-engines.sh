#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UPSTREAM_ROOT="${FUSION_UPSTREAM_ROOT:-/root/opensrc/agent-security-landscape}"
AIG_SOURCE_ROOT="${FUSION_AIG_SOURCE_ROOT:-/root/opensrc/AI-Infra-Guard}"
PYTHON="${FUSION_PYTHON:-python3}"
FORCE_AIG_SOURCE="${FUSION_FORCE_AIG_SOURCE:-0}"

install_engine() {
  local name="$1"
  local source="$2"
  local package="$3"
  local venv="$ROOT/.venvs/$name"
  if [[ -x "$venv/bin/$name" ]]; then
    if [[ "$name" != aig-* || "$FORCE_AIG_SOURCE" != "1" ]]; then
      printf '已就绪 %-14s %s\n' "$name" "$venv/bin/$name"
      return 0
    fi
  fi
  "$PYTHON" -m venv "$venv"
  if [[ -f "$source/pyproject.toml" ]]; then
    "$venv/bin/python" -m pip install --disable-pip-version-check -e "$source"
    printf '已安装 %-14s 源码 %s\n' "$name" "$source"
  else
    "$venv/bin/python" -m pip install --disable-pip-version-check "$package"
    printf '已安装 %-14s 包 %s\n' "$name" "$package"
  fi
}

install_engine skillspector "$UPSTREAM_ROOT/SkillSpector" "skillspector==2.12.0"
install_engine snyk-agent-scan "$UPSTREAM_ROOT/agent-scan" "snyk-agent-scan==0.6.11"
install_engine mcp-scanner "$UPSTREAM_ROOT/mcp-scanner" "cisco-ai-mcp-scanner==4.8.7"
install_engine aig-skill-scan "$AIG_SOURCE_ROOT/skill-scan" "aig-skill-scan==0.2.2"
install_engine aig-mcp-scan "$AIG_SOURCE_ROOT/mcp-scan" "aig-mcp-scan==0.2.0"
install_engine aig-agent-scan "$AIG_SOURCE_ROOT/agent-scan" "aig-agent-scan==0.1.0"

printf '\n引擎依赖已隔离安装到 %s/.venvs\n' "$ROOT"
printf '运行 scripts/run-local.sh 启动平台。\n'
