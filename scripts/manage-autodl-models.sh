#!/usr/bin/env bash
set -euo pipefail

AUTODL_HOST="${LLMSEC_AUTODL_HOST:-region-9.autodl.pro}"
AUTODL_PORT="${LLMSEC_AUTODL_PORT:-16214}"
AUTODL_USER="${LLMSEC_AUTODL_USER:-root}"
AUTODL_KEY="${LLMSEC_AUTODL_KEY:-/root/.ssh/llmsec_autodl}"
TUNNEL_PORT="${LLMSEC_AUTODL_TUNNEL_PORT:-18000}"
HF_ENDPOINT="${LLMSEC_HF_ENDPOINT:-${HF_ENDPOINT:-}}"
ACTION="${1:-status}"
MODEL="${2:-qwen3:8b}"

usage() {
  cat <<'USAGE'
Usage:
  scripts/manage-autodl-models.sh [status|smoke|download|start|stop] [model]

Models:
  qwen3:8b      -> Qwen/Qwen3-8B
  mistral-7b    -> mistralai/Mistral-7B-Instruct-v0.3

Cost-friendly workflow:
  status        Read-only Tencent + AutoDL status.
  smoke         Read-only /v1/models + minimal chat completion through Tencent tunnel.
  download      Cache model under /root/autodl-tmp/hf while AutoDL is already on.
  start         Start one vLLM model on AutoDL. One model should run at a time.
  stop          Stop the current vLLM process on AutoDL.

Optional environment:
  LLMSEC_HF_ENDPOINT=https://hf-mirror.com
USAGE
}

case "${ACTION}" in
  status|smoke|download|start|stop) ;;
  -h|--help|help)
    usage
    exit 0
    ;;
  *)
    echo "Unknown action: ${ACTION}" >&2
    usage >&2
    exit 2
    ;;
esac

case "${MODEL}" in
  qwen3:8b)
    HF_REPO="Qwen/Qwen3-8B"
    SERVED_MODEL="qwen3:8b"
    MAX_MODEL_LEN="${LLMSEC_AUTODL_MAX_MODEL_LEN:-4096}"
    GPU_MEMORY_UTILIZATION="${LLMSEC_AUTODL_GPU_MEMORY_UTILIZATION:-0.85}"
    ;;
  mistral-7b)
    HF_REPO="mistralai/Mistral-7B-Instruct-v0.3"
    SERVED_MODEL="mistral-7b"
    MAX_MODEL_LEN="${LLMSEC_AUTODL_MAX_MODEL_LEN:-4096}"
    GPU_MEMORY_UTILIZATION="${LLMSEC_AUTODL_GPU_MEMORY_UTILIZATION:-0.82}"
    ;;
  *)
    echo "Unsupported model: ${MODEL}" >&2
    usage >&2
    exit 2
    ;;
esac

ssh_args=(
  -o BatchMode=yes
  -o ConnectTimeout=10
  -o StrictHostKeyChecking=accept-new
  -p "${AUTODL_PORT}"
)
scp_args=(-P "${AUTODL_PORT}" -o BatchMode=yes -o StrictHostKeyChecking=accept-new)
if [[ -n "${AUTODL_KEY}" && -f "${AUTODL_KEY}" ]]; then
  ssh_args+=(-i "${AUTODL_KEY}")
  scp_args+=(-i "${AUTODL_KEY}")
fi

target="${AUTODL_USER}@${AUTODL_HOST}"

remote_model_manager='
set -euo pipefail
action="$1"
model="$2"
hf_repo="$3"
served_model="$4"
max_model_len="$5"
gpu_memory_utilization="$6"
hf_endpoint="$7"

export HF_HOME=/root/autodl-tmp/hf
export TRANSFORMERS_CACHE=/root/autodl-tmp/hf/transformers
export HUGGINGFACE_HUB_CACHE=/root/autodl-tmp/hf/hub
if [[ -n "${hf_endpoint}" ]]; then
  export HF_ENDPOINT="${hf_endpoint}"
fi
mkdir -p /root/autodl-tmp/bin /root/autodl-tmp/logs "${HF_HOME}"

vllm_pids() {
  ps -eo pid,args | awk "/python -m vllm.entrypoints.openai.api_server/ && !/awk/ {print \$1}"
}

model_cache_state() {
  repo_dir="$(model_repo_dir)"
  if [[ -d "${repo_dir}" ]]; then
    echo "cache=present ${repo_dir}"
  else
    echo "cache=missing ${repo_dir}"
  fi
}

model_repo_dir() {
  echo "/root/autodl-tmp/hf/hub/models--${hf_repo//\//--}"
}

model_runtime_ref() {
  repo_dir="$(model_repo_dir)"
  if [[ -d "${repo_dir}/snapshots" ]]; then
    snapshot="$(find "${repo_dir}/snapshots" -mindepth 1 -maxdepth 1 -type d | sort | tail -n 1)"
    if [[ -n "${snapshot}" ]]; then
      echo "${snapshot}"
      return
    fi
  fi
  echo "${hf_repo}"
}

write_launcher() {
  model_ref="$(model_runtime_ref)"
  cat > "/root/autodl-tmp/bin/start-vllm-${served_model//[:\/]/-}.sh" <<SH
#!/usr/bin/env bash
set -euo pipefail
export HF_HOME=/root/autodl-tmp/hf
export TRANSFORMERS_CACHE=/root/autodl-tmp/hf/transformers
export HUGGINGFACE_HUB_CACHE=/root/autodl-tmp/hf/hub
if [[ -n "${hf_endpoint}" ]]; then
  export HF_ENDPOINT="${hf_endpoint}"
fi
exec /root/miniconda3/bin/python -m vllm.entrypoints.openai.api_server \\
  --host 127.0.0.1 \\
  --port 8000 \\
  --model "${model_ref}" \\
  --served-model-name "${served_model}" \\
  --trust-remote-code \\
  --dtype half \\
  --max-model-len "${max_model_len}" \\
  --gpu-memory-utilization "${gpu_memory_utilization}"
SH
  chmod +x "/root/autodl-tmp/bin/start-vllm-${served_model//[:\/]/-}.sh"
  echo "/root/autodl-tmp/bin/start-vllm-${served_model//[:\/]/-}.sh"
}

case "${action}" in
  status|smoke)
    date
    hostname
    df -hT /root/autodl-tmp || true
    command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi || true
    echo "model=${model}"
    echo "hf_endpoint=${HF_ENDPOINT:-default}"
    model_cache_state
    echo "runtime_ref=$(model_runtime_ref)"
    ps -eo pid,etime,stat,%cpu,%mem,args | awk "/python -m vllm.entrypoints.openai.api_server/ && !/awk/ {print}" || true
    curl -sS --max-time 5 http://127.0.0.1:8000/v1/models || true
    ;;
  download)
    /root/miniconda3/bin/python - <<PY
from huggingface_hub import snapshot_download
snapshot_download(repo_id="${hf_repo}", cache_dir="/root/autodl-tmp/hf/hub")
PY
    model_cache_state
    ;;
  start)
    if curl -sS --max-time 3 http://127.0.0.1:8000/v1/models >/dev/null 2>&1; then
      current="$(curl -sS --max-time 3 http://127.0.0.1:8000/v1/models || true)"
      if printf "%s" "${current}" | grep -q "\"id\":\"${served_model}\""; then
        echo "vllm=already_running ${served_model}"
        exit 0
      fi
      echo "A different vLLM model is already running. Run stop first before switching." >&2
      echo "${current}" >&2
      exit 3
    fi
    launcher="$(write_launcher)"
    : > "/root/autodl-tmp/logs/vllm-${served_model//[:\/]/-}-current.log"
    nohup "${launcher}" > "/root/autodl-tmp/logs/vllm-${served_model//[:\/]/-}-current.log" 2>&1 < /dev/null &
    echo "vllm_started_pid=$!"
    ;;
  stop)
    pids="$(vllm_pids | xargs || true)"
    if [[ -z "${pids}" ]]; then
      echo "vllm=not_running"
      exit 0
    fi
    kill ${pids}
    echo "vllm_stopped_pids=${pids}"
    ;;
esac
'

echo "== Tencent status =="
systemctl is-active llmsec-backend || true
ss -ltnp | grep -E ":(8000|${TUNNEL_PORT})" || true
curl -sS --max-time 5 "http://127.0.0.1:${TUNNEL_PORT}/v1/models" || true
echo

echo "== AutoDL ${ACTION} ${MODEL} =="
ssh "${ssh_args[@]}" "${target}" \
  "bash -s -- '${ACTION}' '${MODEL}' '${HF_REPO}' '${SERVED_MODEL}' '${MAX_MODEL_LEN}' '${GPU_MEMORY_UTILIZATION}' '${HF_ENDPOINT}'" \
  <<< "${remote_model_manager}"

if [[ "${ACTION}" == "smoke" ]]; then
  echo
  echo "== Tencent tunnel smoke =="
  curl -fsS --max-time 10 "http://127.0.0.1:${TUNNEL_PORT}/v1/models"
  echo
  curl -fsS --max-time 120 "http://127.0.0.1:${TUNNEL_PORT}/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer dummy" \
    -d "{\"model\":\"${SERVED_MODEL}\",\"messages\":[{\"role\":\"user\",\"content\":\"Say READY in one short sentence.\"}],\"max_tokens\":64,\"temperature\":0}"
  echo
fi
