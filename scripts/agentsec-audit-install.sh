#!/usr/bin/env bash
# Load agentsec auditd rules into the running kernel. Requires root.
# Prefers augenrules (Debian/Ubuntu, persistent across reboots) and falls
# back to auditctl -R (volatile, lost on reboot).
set -euo pipefail

RULES_SRC="$(cd "$(dirname "$0")" && pwd)/agentsec-audit.rules"
RULES_DEST="/etc/audit/rules.d/99-agentsec.rules"

if [[ $EUID -ne 0 ]]; then
    echo "error: must run as root (audit rules affect the whole host)" >&2
    exit 1
fi
if ! command -v augenrules >/dev/null 2>&1 && ! command -v auditctl >/dev/null 2>&1; then
    echo "error: auditd not installed (apt install auditd)" >&2
    exit 1
fi

if command -v augenrules >/dev/null 2>&1; then
    install -Dm 0640 "$RULES_SRC" "$RULES_DEST"
    augenrules --load
    echo "installed via augenrules: $RULES_DEST (persists across reboots)"
else
    auditctl -R "$RULES_SRC"
    echo "installed via auditctl -R (volatile; re-run after reboot)"
fi

loaded="$(auditctl -l 2>/dev/null | grep -c agentsec || true)"
if [[ "$loaded" -gt 0 ]]; then
    echo "verified: $loaded agentsec rules active (auditctl -l | grep agentsec)"
else
    echo "warning: no agentsec rules visible in auditctl -l; check auditd status" >&2
fi
echo "uninstall: bash ${0%/*}/agentsec-audit-uninstall.sh"
