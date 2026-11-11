#!/usr/bin/env bash
set -euo pipefail
TASK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec "$TASK_ROOT/.venvs/control-plane/bin/python" "$TASK_ROOT/scripts/e2e-hook-timeline.py"
