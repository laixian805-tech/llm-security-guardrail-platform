#!/usr/bin/env bash
set -euo pipefail

AUTODL_HOST="${LLMSEC_AUTODL_HOST:-region-9.autodl.pro}"
AUTODL_PORT="${LLMSEC_AUTODL_PORT:-16214}"
AUTODL_USER="${LLMSEC_AUTODL_USER:-root}"
AUTODL_KEY="${LLMSEC_AUTODL_KEY:-/root/.ssh/llmsec_autodl}"
APPLY=0

usage() {
  cat <<'USAGE'
Usage:
  scripts/stop-autodl-compute.sh [--apply]

Default mode previews AutoDL compute processes that would be stopped.
Use --apply before shutting down AutoDL to stop vLLM/Garak cleanly.
No files are deleted.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply)
      APPLY=1
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

remote_preview='ps -eo pid,ppid,etime,stat,%cpu,%mem,args | grep -E "python -m vllm.entrypoints.openai.api_server|python -m garak|run-garak-on-autodl" | grep -v grep || true'

echo "== AutoDL compute stop preview =="
ssh "${ssh_args[@]}" "${target}" "${remote_preview}"

if [[ "${APPLY}" -ne 1 ]]; then
  echo
  echo "Preview only. Re-run with --apply to send SIGTERM to the listed compute processes."
  exit 0
fi

echo "== Stopping AutoDL compute processes =="
ssh "${ssh_args[@]}" "${target}" <<'REMOTE'
set -euo pipefail
pids="$(ps -eo pid,args | grep -E 'python -m vllm.entrypoints.openai.api_server|python -m garak|run-garak-on-autodl' | grep -v grep | awk '{print $1}' || true)"
if [[ -z "${pids}" ]]; then
  echo "No AutoDL compute processes found."
  exit 0
fi
echo "Terminating: ${pids}"
kill -TERM ${pids} || true
sleep 5
remaining="$(ps -eo pid,args | grep -E 'python -m vllm.entrypoints.openai.api_server|python -m garak|run-garak-on-autodl' | grep -v grep | awk '{print $1}' || true)"
if [[ -n "${remaining}" ]]; then
  echo "Still running after SIGTERM: ${remaining}"
  exit 1
fi
echo "AutoDL compute processes stopped."
REMOTE

