#!/usr/bin/env bash
set -euo pipefail

RUNNER_ROOT="${LLMSEC_AUTODL_RUNNER_ROOT:-/root/autodl-tmp/llmsec-runner}"
ENV_FILE="${RUNNER_ROOT}/config/runner.env"
if [[ -f "${ENV_FILE}" ]]; then
  set -a
  source "${ENV_FILE}"
  set +a
fi

VENV_DIR="${LLMSEC_AUTODL_VENV_DIR:-${RUNNER_ROOT}/.venv_eval_system}"
VENV_PYTHON="${VENV_DIR}/bin/python"
REPORTS_DIR="${LLMSEC_AUTODL_REPORTS_DIR:-${RUNNER_ROOT}/reports}"
SERVICE_BASE_URL="${LLMSEC_SERVICE_BASE_URL:-http://43.139.77.64:8000}"
MODEL="${LLMSEC_OPENAI_MODEL:-qwen3:8b}"
GUARD_MODE="${LLMSEC_GUARD_MODE:-enforce}"
GARAK_PROBES="${LLMSEC_GARAK_PROBES:-promptinject.HijackHateHumans}"
TIMEOUT_SECONDS="${LLMSEC_GARAK_TIMEOUT_SECONDS:-3600}"
RUN_ID="${LLMSEC_RUN_ID:-garak-autodl-$(date +%Y%m%d-%H%M%S)}"
RUN_DIR="${REPORTS_DIR}/${RUN_ID}"

usage() {
  cat <<'USAGE'
Usage:
  scripts/run-garak-on-autodl.sh [--guard-mode off|audit|enforce] [--probes SPEC] [--model MODEL] [--service-base-url URL] [--run-id ID]

Environment defaults live in /root/autodl-tmp/llmsec-runner/config/runner.env.
Use narrow probe specs first, then run broader Garak suites intentionally.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --guard-mode)
      GUARD_MODE="${2:-}"
      shift 2
      ;;
    --probes)
      GARAK_PROBES="${2:-}"
      shift 2
      ;;
    --model)
      MODEL="${2:-}"
      shift 2
      ;;
    --service-base-url)
      SERVICE_BASE_URL="${2:-}"
      shift 2
      ;;
    --run-id)
      RUN_ID="${2:-}"
      RUN_DIR="${REPORTS_DIR}/${RUN_ID}"
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

if [[ ! -x "${VENV_PYTHON}" ]]; then
  echo "Missing runner venv: ${VENV_PYTHON}. Run scripts/bootstrap-autodl-runner.sh first." >&2
  exit 1
fi

mkdir -p "${RUN_DIR}"
CONFIG_PATH="${RUN_DIR}/garak-config.json"
REPORT_PREFIX="${RUN_DIR}/garak"

cat > "${CONFIG_PATH}" <<JSON
{
  "system": {
    "lite": true,
    "narrow_output": true,
    "parallel_attempts": 1,
    "parallel_requests": 1,
    "show_z": false,
    "verbose": 0
  },
  "run": {
    "generations": 1,
    "eval_threshold": 0.5
  },
  "plugins": {
    "generators": {
      "openai": {
        "OpenAICompatible": {
          "name": "${MODEL}",
          "uri": "${SERVICE_BASE_URL%/}/v1/",
          "temperature": 0.0,
          "retry_json": true,
          "extra_params": {
            "extra_body": {"guard_mode": "${GUARD_MODE}"}
          }
        }
      }
    }
  },
  "reporting": {
    "report_dir": "${RUN_DIR}",
    "taxonomy": null,
    "report_prefix": "${REPORT_PREFIX}"
  }
}
JSON

export OPENAICOMPATIBLE_API_KEY="${OPENAICOMPATIBLE_API_KEY:-dummy}"

echo "Running Garak on AutoDL runner"
echo "  run_id=${RUN_ID}"
echo "  service=${SERVICE_BASE_URL}"
echo "  model=${MODEL}"
echo "  guard_mode=${GUARD_MODE}"
echo "  probes=${GARAK_PROBES}"
echo "  run_dir=${RUN_DIR}"

timeout "${TIMEOUT_SECONDS}" "${VENV_PYTHON}" -m garak \
  --config "${CONFIG_PATH}" \
  --target_type openai.OpenAICompatible \
  --target_name "${MODEL}" \
  --probes "${GARAK_PROBES}" \
  --report_prefix "${REPORT_PREFIX}" \
  --parallel_attempts 1 \
  --parallel_requests 1 \
  --generations 1 \
  --narrow_output \
  > "${RUN_DIR}/garak.stdout.log" \
  2> "${RUN_DIR}/garak.stderr.log"

if [[ ! -f "${RUN_DIR}/garak.report.jsonl" ]]; then
  echo "Garak finished without ${RUN_DIR}/garak.report.jsonl" >&2
  echo "See ${RUN_DIR}/garak.stdout.log and ${RUN_DIR}/garak.stderr.log" >&2
  exit 1
fi

cat > "${RUN_DIR}/autodl-run-manifest.json" <<JSON
{
  "run_id": "${RUN_ID}",
  "adapter": "garak",
  "guard_mode": "${GUARD_MODE}",
  "model": "${MODEL}",
  "service_base_url": "${SERVICE_BASE_URL}",
  "probes": "${GARAK_PROBES}",
  "report_dir": "${RUN_DIR}",
  "created_at": "$(date -Iseconds)"
}
JSON

echo "Garak report ready: ${RUN_DIR}"
