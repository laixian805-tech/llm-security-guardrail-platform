#!/usr/bin/env bash
set -euo pipefail

RUNNER_ROOT="${LLMSEC_AUTODL_RUNNER_ROOT:-/root/autodl-tmp/llmsec-runner}"
VENV_DIR="${LLMSEC_AUTODL_VENV_DIR:-${RUNNER_ROOT}/.venv_eval_system}"
REPORTS_DIR="${LLMSEC_AUTODL_REPORTS_DIR:-${RUNNER_ROOT}/reports}"
CONFIG_DIR="${RUNNER_ROOT}/config"
BIN_DIR="${RUNNER_ROOT}/bin"
ENV_FILE="${CONFIG_DIR}/runner.env"

if [[ -d /root/miniconda3/bin ]]; then
  export PATH="/root/miniconda3/bin:${PATH}"
fi

if command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="$(command -v python3)"
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN="$(command -v python)"
elif [[ -x /root/miniconda3/bin/python ]]; then
  PYTHON_BIN="/root/miniconda3/bin/python"
else
  echo "No Python interpreter found. Expected python3, python, or /root/miniconda3/bin/python." >&2
  exit 1
fi

mkdir -p "${REPORTS_DIR}" "${CONFIG_DIR}" "${BIN_DIR}"

if [[ ! -d "${VENV_DIR}" ]]; then
  venv_args=()
  if "${PYTHON_BIN}" -c "import torch" >/dev/null 2>&1; then
    venv_args+=(--system-site-packages)
  fi
  "${PYTHON_BIN}" -m venv "${venv_args[@]}" "${VENV_DIR}"
fi

"${VENV_DIR}/bin/python" -m pip install --upgrade --prefer-binary pip wheel setuptools
"${VENV_DIR}/bin/python" -m pip install --upgrade --prefer-binary garak httpx pydantic pydantic-settings

if command -v npm >/dev/null 2>&1; then
  if ! command -v promptfoo >/dev/null 2>&1; then
    npm install -g promptfoo
  fi
else
  echo "npm is not available; Promptfoo will be skipped until Node.js/npm is installed." >&2
fi

cat > "${ENV_FILE}" <<ENV
LLMSEC_SERVICE_BASE_URL=${LLMSEC_SERVICE_BASE_URL:-http://43.139.77.64:8000}
LLMSEC_OPENAI_MODEL=${LLMSEC_OPENAI_MODEL:-qwen3:8b}
LLMSEC_AUTODL_VENV_DIR=${VENV_DIR}
LLMSEC_AUTODL_REPORTS_DIR=${REPORTS_DIR}
LLMSEC_GARAK_TIMEOUT_SECONDS=${LLMSEC_GARAK_TIMEOUT_SECONDS:-3600}
LLMSEC_PYTHON_BIN=${PYTHON_BIN}
ENV

cat > "${BIN_DIR}/activate-runner" <<EOF
#!/usr/bin/env bash
if [[ -d /root/miniconda3/bin ]]; then
  export PATH="/root/miniconda3/bin:\${PATH}"
fi
source "${VENV_DIR}/bin/activate"
set -a
source "${ENV_FILE}"
set +a
EOF
chmod +x "${BIN_DIR}/activate-runner"

echo "AutoDL runner bootstrapped."
echo "Runner root: ${RUNNER_ROOT}"
echo "Reports dir: ${REPORTS_DIR}"
echo "Env file: ${ENV_FILE}"
echo "Activate with: source ${BIN_DIR}/activate-runner"
