#!/usr/bin/env bash
set -euo pipefail

RUNNER_ROOT="${LLMSEC_AUTODL_RUNNER_ROOT:-/root/autodl-tmp/llmsec-runner}"
SOURCE_DIR="${LLMSEC_AUTODL_REPORTS_DIR:-${RUNNER_ROOT}/reports}"
TENCENT_HOST="${LLMSEC_TENCENT_HOST:-43.139.77.64}"
TENCENT_USER="${LLMSEC_TENCENT_USER:-root}"
TENCENT_REPORTS_DIR="${LLMSEC_TENCENT_REPORTS_DIR:-/root/llmsec-assets/reports/autodl}"
SSH_KEY="${LLMSEC_TENCENT_SSH_KEY:-}"
APPLY=0

usage() {
  cat <<'USAGE'
Usage:
  scripts/sync-reports-to-tencent.sh [--apply] [--source DIR] [--target HOST:/path]

Default mode is dry-run. Set LLMSEC_TENCENT_SSH_KEY or rely on the default SSH agent/key.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply)
      APPLY=1
      shift
      ;;
    --source)
      SOURCE_DIR="${2:-}"
      shift 2
      ;;
    --target)
      target="${2:-}"
      TENCENT_HOST="${target%%:*}"
      TENCENT_REPORTS_DIR="${target#*:}"
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

if [[ ! -d "${SOURCE_DIR}" ]]; then
  echo "Missing source reports dir: ${SOURCE_DIR}" >&2
  exit 1
fi

ssh_args=(-o StrictHostKeyChecking=accept-new)
if [[ -n "${SSH_KEY}" ]]; then
  ssh_args+=(-i "${SSH_KEY}")
fi
ssh_command="ssh"
for arg in "${ssh_args[@]}"; do
  ssh_command+=" ${arg}"
done

target="${TENCENT_USER}@${TENCENT_HOST}:${TENCENT_REPORTS_DIR}/"
echo "Report sync preview:"
echo "  source: ${SOURCE_DIR}/"
echo "  target: ${target}"

if [[ "${APPLY}" -ne 1 ]]; then
  echo "  command: rsync -av -e '${ssh_command}' '${SOURCE_DIR}/' '${target}'"
  echo
  echo "Files that would be considered for sync:"
  find "${SOURCE_DIR}" -maxdepth 2 -type f | sort | sed -n '1,80p'
  echo
  echo "Dry-run only. Re-run with --apply to sync reports."
  exit 0
fi

if command -v rsync >/dev/null 2>&1; then
  ssh "${ssh_args[@]}" "${TENCENT_USER}@${TENCENT_HOST}" "mkdir -p '${TENCENT_REPORTS_DIR}'"
  rsync -av -e "${ssh_command}" "${SOURCE_DIR}/" "${target}"
else
  ssh "${ssh_args[@]}" "${TENCENT_USER}@${TENCENT_HOST}" "mkdir -p '${TENCENT_REPORTS_DIR}'"
  scp "${ssh_args[@]}" -r "${SOURCE_DIR}/." "${target}"
fi
