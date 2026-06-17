#!/usr/bin/env bash
set -euo pipefail

AUTODL_HOST="${LLMSEC_AUTODL_HOST:-region-9.autodl.pro}"
AUTODL_PORT="${LLMSEC_AUTODL_PORT:-16214}"
AUTODL_USER="${LLMSEC_AUTODL_USER:-root}"
AUTODL_KEY="${LLMSEC_AUTODL_KEY:-/root/.ssh/llmsec_autodl}"
TUNNEL_PORT="${LLMSEC_AUTODL_TUNNEL_PORT:-18000}"
START_VLLM=0

usage() {
  cat <<'USAGE'
Usage:
  scripts/check-autodl-recovery.sh [--start-vllm]

Environment:
  LLMSEC_AUTODL_HOST=region-9.autodl.pro
  LLMSEC_AUTODL_PORT=16214
  LLMSEC_AUTODL_USER=root
  LLMSEC_AUTODL_KEY=/root/.ssh/llmsec_autodl
  LLMSEC_AUTODL_TUNNEL_PORT=18000

Default mode is read-only status checking. Use --start-vllm to start the
AutoDL vLLM service if AutoDL is reachable but the model API is down.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --start-vllm)
      START_VLLM=1
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

autodl_target="${AUTODL_USER}@${AUTODL_HOST}"

echo "== Tencent status =="
date
systemctl is-active llmsec-backend || true
systemctl is-enabled llmsec-backend || true
ss -ltnp | grep -E ":(8000|${TUNNEL_PORT})" || true
curl -sS --max-time 8 http://127.0.0.1:8000/health || true
echo

echo "== AutoDL SSH =="
if ! ssh "${ssh_args[@]}" "${autodl_target}" "date; hostname" ; then
  cat <<EOF

AutoDL is not reachable through:
  ssh -p ${AUTODL_PORT} ${autodl_target}

Likely causes:
  - AutoDL is powered off.
  - AutoDL host or SSH port changed after restart.
  - Tencent SSH key is not accepted by AutoDL.

After AutoDL is powered on, rerun this script. If host/port changed, pass:
  LLMSEC_AUTODL_HOST=<host> LLMSEC_AUTODL_PORT=<port> bash scripts/check-autodl-recovery.sh
EOF
  exit 1
fi

read -r -d '' REMOTE_CHECK <<'REMOTE' || true
set -euo pipefail

echo "== AutoDL persistent assets =="
df -hT /root/autodl-tmp || true
test -d /root/autodl-tmp/hf/hub/models--Qwen--Qwen3-8B && echo "model_cache=ok" || echo "model_cache=missing"
test -x /root/autodl-tmp/llmsec-runner/.venv_eval_system/bin/python && echo "runner_venv=ok" || echo "runner_venv=missing"
test -x /root/autodl-tmp/bin/start-vllm-qwen3.sh && echo "vllm_launcher=ok" || echo "vllm_launcher=missing"

if [[ -x /root/autodl-tmp/llmsec-runner/.venv_eval_system/bin/python ]]; then
  /root/autodl-tmp/llmsec-runner/.venv_eval_system/bin/python - <<'PY'
import importlib.util
for name in ["garak", "torch", "httpx", "pydantic"]:
    print(f"{name}={importlib.util.find_spec(name) is not None}")
PY
fi

echo "== AutoDL vLLM =="
ps -eo pid,ppid,etime,stat,%cpu,%mem,args | awk '/python -m vllm.entrypoints.openai.api_server/ && !/awk/ {print}' || true
curl -sS --max-time 5 http://127.0.0.1:8000/v1/models || true
echo
REMOTE

ssh "${ssh_args[@]}" "${autodl_target}" "${REMOTE_CHECK}"

if [[ "${START_VLLM}" -eq 1 ]]; then
  echo "== Starting AutoDL vLLM if needed =="
  ssh "${ssh_args[@]}" "${autodl_target}" <<'REMOTE'
set -euo pipefail
mkdir -p /root/autodl-tmp/logs /root/autodl-tmp/bin

cat > /root/autodl-tmp/bin/start-vllm-qwen3.sh <<'SH'
#!/usr/bin/env bash
set -euo pipefail
export HF_HOME=/root/autodl-tmp/hf
export TRANSFORMERS_CACHE=/root/autodl-tmp/hf/transformers
export HUGGINGFACE_HUB_CACHE=/root/autodl-tmp/hf/hub
MODEL_PATH=/root/autodl-tmp/hf/hub/models--Qwen--Qwen3-8B/snapshots/b968826d9c46dd6066d109eabc6255188de91218
exec /root/miniconda3/bin/python -m vllm.entrypoints.openai.api_server \
  --host 127.0.0.1 \
  --port 8000 \
  --model "${MODEL_PATH}" \
  --served-model-name qwen3:8b \
  --trust-remote-code \
  --dtype half \
  --max-model-len 4096 \
  --gpu-memory-utilization 0.85
SH
chmod +x /root/autodl-tmp/bin/start-vllm-qwen3.sh

if curl -sS --max-time 3 http://127.0.0.1:8000/v1/models >/dev/null 2>&1; then
  echo "vllm=already_ready"
elif pgrep -f '^/root/miniconda3/bin/python -m vllm.entrypoints.openai.api_server' >/dev/null; then
  echo "vllm=already_starting"
else
  : > /root/autodl-tmp/logs/vllm-qwen3-current.log
  nohup /root/autodl-tmp/bin/start-vllm-qwen3.sh > /root/autodl-tmp/logs/vllm-qwen3-current.log 2>&1 < /dev/null &
  echo "vllm_started_pid=$!"
fi
REMOTE

  echo "Waiting for AutoDL vLLM /v1/models..."
  for _ in $(seq 1 40); do
    if ssh "${ssh_args[@]}" "${autodl_target}" "curl -sS --max-time 5 http://127.0.0.1:8000/v1/models" ; then
      echo
      break
    fi
    sleep 15
  done
fi

echo "== Tencent tunnel check =="
if curl -sS --max-time 5 "http://127.0.0.1:${TUNNEL_PORT}/v1/models" ; then
  echo
else
  echo "Tunnel check failed. Restart or recreate the SSH local forward to AutoDL." >&2
  exit 1
fi

echo "Recovery check complete."
