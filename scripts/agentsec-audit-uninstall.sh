#!/usr/bin/env bash
# Remove agentsec auditd rules. Requires root. Never deletes rules that do
# not belong to agentsec.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "error: must run as root" >&2
    exit 1
fi

if [[ -f /etc/audit/rules.d/99-agentsec.rules ]]; then
    rm -f /etc/audit/rules.d/99-agentsec.rules
    augenrules --load
    echo "removed /etc/audit/rules.d/99-agentsec.rules and reloaded rules"
    exit 0
fi

# auditctl fallback: only wipe everything when every active rule is ours.
if command -v auditctl >/dev/null 2>&1; then
    total="$(auditctl -l 2>/dev/null | grep -c . || true)"
    ours="$(auditctl -l 2>/dev/null | grep -c agentsec || true)"
    if [[ "$total" -eq 0 ]]; then
        echo "no audit rules active"
        exit 0
    fi
    if [[ "$total" -eq "$ours" ]]; then
        auditctl -D
        echo "removed $ours agentsec rules via auditctl -D"
    else
        echo "refusing to run auditctl -D: $((total - ours)) non-agentsec rules are active." >&2
        echo "remove the agentsec rules manually:" >&2
        auditctl -l 2>/dev/null | grep agentsec >&2 || true
        exit 1
    fi
    exit 0
fi
echo "nothing to do (no augenrules rules file, no auditctl)" >&2
