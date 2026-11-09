#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="agentsec-test-collector"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

if [[ $EUID -ne 0 ]]; then
  echo "error: run as root" >&2
  exit 1
fi
if [[ $# -ne 2 ]]; then
  echo "usage: $0 <test-user> <central-events-url>" >&2
  exit 2
fi

TEST_USER="$1"
UPLOAD_URL="$2"
case "$UPLOAD_URL" in
  https://*) ;;
  http://127.0.0.1:*|http://localhost:*) ;;
  *) echo "error: central URL must use HTTPS or loopback HTTP" >&2; exit 2 ;;
esac

HOME_DIR="$(getent passwd "$TEST_USER" | cut -d: -f6)"
TEST_UID="$(id -u "$TEST_USER")"
EDGE_ROOT="${AGENTSEC_EDGE_HOME:-$HOME_DIR/.local/share/agentsec}"
VENV_ROOT="${AGENTSEC_EDGE_VENV:-$HOME_DIR/.local/venvs/agentsec}"
STATE_DIR="${AGENTSEC_HOME_OVERRIDE:-$HOME_DIR/.agentsec}"
TOKEN_FILE="$HOME_DIR/.config/agentsec-lab/agentsec.env"

if [[ -z "$HOME_DIR" || ! -x "$VENV_ROOT/bin/python" || ! -r "$TOKEN_FILE" ]]; then
  echo "error: edge bundle/venv or device credential file missing for $TEST_USER" >&2
  exit 1
fi
if [[ "$(stat -c '%a' "$TOKEN_FILE")" != "600" ]]; then
  echo "error: device credential file must have mode 600" >&2
  exit 1
fi
if ! systemctl is-active --quiet auditd; then
  echo "error: auditd must be active first" >&2
  exit 1
fi
if ! auditctl -l | grep -q agentsec_test; then
  echo "error: test-scoped audit rules are not active" >&2
  exit 1
fi

install -d -o "$TEST_USER" -g "$(id -gn "$TEST_USER")" -m 0700 "$STATE_DIR"
chown -R "$TEST_USER:$(id -gn "$TEST_USER")" "$STATE_DIR"
chmod 0700 "$STATE_DIR"
find "$STATE_DIR" -type f -exec chmod 0600 {} +
chown -R "$TEST_USER:$(id -gn "$TEST_USER")" "$STATE_DIR"
chmod 0700 "$STATE_DIR"
find "$STATE_DIR" -type f -exec chmod 0600 {} +
cat >"$SERVICE_FILE" <<EOF
[Unit]
Description=AgentSec test collector for ${TEST_USER}
After=auditd.service network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${TEST_USER}
Group=${TEST_USER}
SupplementaryGroups=adm
WorkingDirectory=${HOME_DIR}/lab
UMask=0077
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONPATH=${EDGE_ROOT}
Environment=AGENTSEC_AUDIT_LOG=/var/log/audit/audit.log
Environment=AGENTSEC_DB_PATH=${STATE_DIR}/agentsec.db
Environment=AGENTSEC_HOME=${STATE_DIR}
Environment=AGENTSEC_HOST=$(hostname)
Environment=AGENTSEC_HOST_ROLE=test
Environment=AGENTSEC_POLL_SECONDS=5
Environment=AGENTSEC_HEARTBEAT_SECONDS=60
Environment=AGENTSEC_UPLOAD_URL=${UPLOAD_URL}
EnvironmentFile=${TOKEN_FILE}
ExecStart=${VENV_ROOT}/bin/python -m agentsec monitor daemon
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
PrivateTmp=true
ReadOnlyPaths=/var/log/audit
ReadWritePaths=${STATE_DIR}

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$SERVICE_FILE"
systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"
systemctl --no-pager --full status "$SERVICE_NAME"
echo "test UID scope: $TEST_UID"
echo "disable: systemctl disable --now $SERVICE_NAME"
