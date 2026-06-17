#!/usr/bin/env bash
set -euo pipefail

AUTODL_HOST="${LLMSEC_AUTODL_HOST:-region-9.autodl.pro}"
AUTODL_PORT="${LLMSEC_AUTODL_PORT:-16214}"
AUTODL_USER="${LLMSEC_AUTODL_USER:-root}"
AUTODL_KEY="${LLMSEC_AUTODL_KEY:-/root/.ssh/llmsec_autodl}"

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

echo "== Syncing AutoDL runner scripts =="
ssh "${ssh_args[@]}" "${target}" "mkdir -p /root/autodl-tmp/llmsec-runner/scripts"
scp -P "${AUTODL_PORT}" \
  ${AUTODL_KEY:+-i "${AUTODL_KEY}"} \
  -o BatchMode=yes \
  -o StrictHostKeyChecking=accept-new \
  scripts/bootstrap-autodl-runner.sh \
  scripts/run-garak-on-autodl.sh \
  scripts/sync-reports-to-tencent.sh \
  "${target}:/root/autodl-tmp/llmsec-runner/scripts/"
ssh "${ssh_args[@]}" "${target}" "chmod +x /root/autodl-tmp/llmsec-runner/scripts/*.sh"

echo "== Bootstrapping AutoDL Garak runner =="
ssh "${ssh_args[@]}" "${target}" "cd /root/autodl-tmp/llmsec-runner && bash scripts/bootstrap-autodl-runner.sh"

echo "== Installing vLLM launcher =="
ssh "${ssh_args[@]}" "${target}" <<'REMOTE'
set -euo pipefail
mkdir -p /root/autodl-tmp/bin /root/autodl-tmp/logs
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
REMOTE

echo "== Verifying AutoDL persistent compute assets =="
bash scripts/sync-autodl-compute-assets.sh --check-only

