#!/usr/bin/env bash
set -euo pipefail

BUNDLE="${1:-}"
if [[ -z "$BUNDLE" || ! -r "$BUNDLE" ]]; then
  echo "usage: $0 <agentsec-edge-bundle.tar.gz>" >&2
  exit 2
fi

EDGE_ROOT="${AGENTSEC_EDGE_HOME:-$HOME/.local/share/agentsec}"
VENV_ROOT="${AGENTSEC_EDGE_VENV:-$HOME/.local/venvs/agentsec}"
mkdir -p "$EDGE_ROOT" "$(dirname "$VENV_ROOT")"
tar -xzf "$BUNDLE" -C "$EDGE_ROOT"
python3 -m venv "$VENV_ROOT"
"$VENV_ROOT/bin/python" -m pip install --disable-pip-version-check \
  -r "$EDGE_ROOT/requirements-agentsec-edge.txt"
chmod 700 "$EDGE_ROOT"
mkdir -p "${AGENTSEC_HOME:-$HOME/.agentsec}"
chmod 700 "${AGENTSEC_HOME:-$HOME/.agentsec}"

printf 'installed package: %s/agentsec\n' "$EDGE_ROOT"
printf 'python: %s/bin/python\n' "$VENV_ROOT"
printf 'run with: PYTHONPATH=%s AGENTSEC_HOME=%s %s/bin/python -m agentsec inventory\n' \
  "$EDGE_ROOT" "${AGENTSEC_HOME:-$HOME/.agentsec}" "$VENV_ROOT"
