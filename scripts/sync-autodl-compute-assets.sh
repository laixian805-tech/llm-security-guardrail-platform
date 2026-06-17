#!/usr/bin/env bash
set -euo pipefail

AUTODL_HOST="${LLMSEC_AUTODL_HOST:-region-9.autodl.pro}"
AUTODL_PORT="${LLMSEC_AUTODL_PORT:-16214}"
AUTODL_USER="${LLMSEC_AUTODL_USER:-root}"
AUTODL_KEY="${LLMSEC_AUTODL_KEY:-/root/.ssh/llmsec_autodl}"
CHECK_ONLY=0

usage() {
  cat <<'USAGE'
Usage:
  scripts/sync-autodl-compute-assets.sh [--check-only]

Checks whether AutoDL compute assets are already persisted under /root/autodl-tmp.
This script does not delete or move data.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --check-only)
      CHECK_ONLY=1
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

ssh_args=(
  -o BatchMode=yes
  -o ConnectTimeout=10
  -o StrictHostKeyChecking=accept-new
  -p "${AUTODL_PORT}"
)
if [[ -n "${AUTODL_KEY}" && -f "${AUTODL_KEY}" ]]; then
  ssh_args+=(-i "${AUTODL_KEY}")
fi

target="${AUTODL_USER}@${AUTODL_HOST}"

ssh "${ssh_args[@]}" "${target}" <<'REMOTE'
set -euo pipefail

echo "== AutoDL persistent disk =="
df -hT /root/autodl-tmp
du -hd1 /root/autodl-tmp 2>/dev/null | sort -h | tail -20

echo "== Required compute assets =="
status=0
check_path() {
  local label="$1"
  local path="$2"
  if [[ -e "$path" ]]; then
    echo "${label}=ok ${path}"
  else
    echo "${label}=missing ${path}"
    status=1
  fi
}

check_path model_cache /root/autodl-tmp/hf/hub/models--Qwen--Qwen3-8B
check_path runner_venv /root/autodl-tmp/llmsec-runner/.venv_eval_system/bin/python
check_path runner_env /root/autodl-tmp/llmsec-runner/config/runner.env
check_path runner_scripts /root/autodl-tmp/llmsec-runner/scripts/run-garak-on-autodl.sh
check_path vllm_launcher /root/autodl-tmp/bin/start-vllm-qwen3.sh
check_path reports_dir /root/autodl-tmp/llmsec-runner/reports

if [[ -x /root/autodl-tmp/llmsec-runner/.venv_eval_system/bin/python ]]; then
  /root/autodl-tmp/llmsec-runner/.venv_eval_system/bin/python - <<'PY'
import importlib.util
for name in ["garak", "torch", "httpx", "pydantic"]:
    ok = importlib.util.find_spec(name) is not None
    print(f"{name}={ok}")
PY
fi

echo "== Running compute processes =="
ps -eo pid,ppid,etime,stat,%cpu,%mem,args | grep -E 'python -m vllm.entrypoints.openai.api_server|python -m garak|run-garak-on-autodl' | grep -v grep || true

echo "== Latest AutoDL reports =="
find /root/autodl-tmp/llmsec-runner/reports -maxdepth 2 -type f -name 'garak.report.jsonl' -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -5 || true

exit "$status"
REMOTE

if [[ "${CHECK_ONLY}" -eq 1 ]]; then
  echo "Check-only mode complete."
fi

