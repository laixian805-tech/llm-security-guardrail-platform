#!/usr/bin/env bash
set -euo pipefail

# Install UID/path-scoped audit rules for an isolated AgentSec test endpoint.
# This deliberately does not load scripts/agentsec-audit.rules, whose broad
# watches are reserved for a dedicated development host.

if [[ $EUID -ne 0 ]]; then
  echo "error: run as root" >&2
  exit 1
fi

TEST_UID="${AGENTSEC_TEST_UID:-}"
TEST_ROOT="${AGENTSEC_TEST_ROOT:-}"
if [[ -z "$TEST_UID" || -z "$TEST_ROOT" ]]; then
  echo "usage: AGENTSEC_TEST_UID=<uid> AGENTSEC_TEST_ROOT=<absolute-dir> $0" >&2
  exit 2
fi
if [[ "$TEST_ROOT" != /* || "$TEST_ROOT" == "/" ]]; then
  echo "error: AGENTSEC_TEST_ROOT must be a non-root absolute directory" >&2
  exit 2
fi
if ! [[ "$TEST_UID" =~ ^[0-9]+$ ]]; then
  echo "error: AGENTSEC_TEST_UID must be numeric" >&2
  exit 2
fi

RULE_FILE="/etc/audit/rules.d/99-agentsec-test.rules"
install -d -m 0750 /etc/audit/rules.d
cat >"$RULE_FILE" <<EOF
# AgentSec test-only rules: effective UID $TEST_UID and path $TEST_ROOT.
-w $TEST_ROOT/ -p rwa -k agentsec_test_assets
-a always,exit -F arch=b64 -S execve -F uid=$TEST_UID -F key=agentsec_test_exec
-a always,exit -F arch=b32 -S execve -F uid=$TEST_UID -F key=agentsec_test_exec
-a always,exit -F arch=b64 -S connect -F uid=$TEST_UID -F key=agentsec_test_net
-a always,exit -F arch=b32 -S connect -F uid=$TEST_UID -F key=agentsec_test_net
EOF
chmod 0640 "$RULE_FILE"
augenrules --load
auditctl -l | grep agentsec_test
echo "installed: $RULE_FILE"
echo "scope: uid=$TEST_UID path=$TEST_ROOT"
