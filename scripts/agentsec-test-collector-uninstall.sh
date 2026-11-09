#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "error: run as root" >&2
  exit 1
fi

SERVICE_NAME="agentsec-test-collector"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
systemctl disable --now "$SERVICE_NAME" 2>/dev/null || true
if [[ -f "$SERVICE_FILE" ]]; then
  rm -f "$SERVICE_FILE"
fi
systemctl daemon-reload
systemctl reset-failed "$SERVICE_NAME" 2>/dev/null || true
echo "collector unit removed; scoped audit rules remain until separately uninstalled"
