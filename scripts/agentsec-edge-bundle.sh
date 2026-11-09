#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT="${1:-${TMPDIR:-/tmp}/agentsec-edge-bundle.tar.gz}"

mkdir -p "$(dirname "$OUTPUT")"
tar -czf "$OUTPUT" \
  --exclude='__pycache__' \
  --exclude='*.pyc' \
  --transform='s,^agent_security,agentsec,' \
  -C "$REPO_ROOT/backend/app" agent_security \
  -C "$REPO_ROOT/backend" requirements-agentsec-edge.txt
printf 'bundle: %s\n' "$OUTPUT"
