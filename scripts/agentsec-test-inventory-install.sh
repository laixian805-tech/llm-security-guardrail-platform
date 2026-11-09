#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "error: run as root" >&2
  exit 1
fi
if [[ $# -ne 2 ]]; then
  echo "usage: $0 <test-user> <central-inventory-url>" >&2
  exit 2
fi

TEST_USER="$1"
INVENTORY_URL="$2"
case "$INVENTORY_URL" in
  https://*) ;;
  http://127.0.0.1:*|http://localhost:*) ;;
  *) echo "error: inventory URL must use HTTPS or loopback HTTP" >&2; exit 2 ;;
esac

HOME_DIR="$(getent passwd "$TEST_USER" | cut -d: -f6)"
VENV_ROOT="${AGENTSEC_EDGE_VENV:-$HOME_DIR/.local/venvs/agentsec}"
EDGE_ROOT="${AGENTSEC_EDGE_HOME:-$HOME_DIR/.local/share/agentsec}"
TOKEN_FILE="$HOME_DIR/.config/agentsec-lab/agentsec.env"
if [[ -z "$HOME_DIR" || ! -x "$VENV_ROOT/bin/python" || ! -r "$TOKEN_FILE" ]]; then
  echo "error: edge bundle or device credential missing for $TEST_USER" >&2
  exit 1
fi
if [[ "$(stat -c '%a' "$TOKEN_FILE")" != "600" ]]; then
  echo "error: device credential file must have mode 600" >&2
  exit 1
fi

install -d -o "$TEST_USER" -g "$(id -gn "$TEST_USER")" -m 0700 "$HOME_DIR/.agentsec"
export HOME_DIR VENV_ROOT EDGE_ROOT TOKEN_FILE INVENTORY_URL TEST_USER
python3 - <<'PY'
import os
import socket
from pathlib import Path

home = Path(os.environ["HOME_DIR"])
unit = f"""[Unit]
Description=AgentSec periodic inventory for {os.environ['TEST_USER']}
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User={os.environ['TEST_USER']}
Group={os.environ['TEST_USER']}
WorkingDirectory={home}/lab
Environment=HOME={home}
Environment=PYTHONPATH={os.environ['EDGE_ROOT']}
Environment=AGENTSEC_HOME={home}/.agentsec
Environment=AGENTSEC_HOST={socket.gethostname()}
Environment=AGENTSEC_OWNER={os.environ['TEST_USER']}
Environment=AGENTSEC_HOST_ROLE=test
Environment=AGENTSEC_ASSET_UPLOAD_URL={os.environ['INVENTORY_URL']}
Environment=PATH={home}/.local/npm/node_modules/.bin:{home}/.local/bin:{home}/.stepcode/bin:{home}/.openclaw/bin:{home}/.openclaw/tools/node/bin:/usr/local/bin:/usr/bin:/bin
EnvironmentFile={os.environ['TOKEN_FILE']}
ExecStart={os.environ['VENV_ROOT']}/bin/python -m agentsec inventory --upload --best-effort --scan {home}/.codex/.tmp/plugins/plugins --scan {home}/.codex/skills --scan {home}/lab/agentsec-assets
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths={home}/.agentsec
ReadOnlyPaths={home}/.codex {home}/lab/agentsec-assets
"""
Path("/etc/systemd/system/agentsec-test-inventory.service").write_text(unit)
Path("/etc/systemd/system/agentsec-test-inventory.timer").write_text("""[Unit]
Description=Refresh AgentSec inventory every five minutes

[Timer]
OnBootSec=90s
OnUnitActiveSec=5min
RandomizedDelaySec=30s
Persistent=true
Unit=agentsec-test-inventory.service

[Install]
WantedBy=timers.target
""")
PY
chmod 0644 /etc/systemd/system/agentsec-test-inventory.{service,timer}
systemctl daemon-reload
systemctl enable --now agentsec-test-inventory.timer
systemctl start agentsec-test-inventory.service
systemctl --no-pager --full status agentsec-test-inventory.timer agentsec-test-inventory.service
