#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "error: run as root" >&2
  exit 1
fi
systemctl disable --now agentsec-test-inventory.timer 2>/dev/null || true
systemctl stop agentsec-test-inventory.service 2>/dev/null || true
for unit in agentsec-test-inventory.timer agentsec-test-inventory.service; do
  [[ -f "/etc/systemd/system/$unit" ]] && rm -f "/etc/systemd/system/$unit"
done
systemctl daemon-reload
echo "AgentSec periodic inventory timer removed"
