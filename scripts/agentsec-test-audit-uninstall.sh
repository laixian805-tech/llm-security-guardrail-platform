#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "error: run as root" >&2
  exit 1
fi

RULE_FILE="/etc/audit/rules.d/99-agentsec-test.rules"
if [[ -f "$RULE_FILE" ]]; then
  rm -f "$RULE_FILE"
  augenrules --load
fi
if auditctl -l | grep -q agentsec_test; then
  echo "warning: agentsec_test rules are still active; reboot or reload audit rules" >&2
else
  echo "removed agentsec_test rules"
fi
