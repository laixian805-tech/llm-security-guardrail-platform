#!/usr/bin/env bash
set -euo pipefail

ASSETS_ROOT="${LLMSEC_ASSETS_ROOT:-/home/tlx/llmsec-assets}"

mkdir -p \
  "$ASSETS_ROOT/models" \
  "$ASSETS_ROOT/ollama" \
  "$ASSETS_ROOT/chroma" \
  "$ASSETS_ROOT/reports" \
  "$ASSETS_ROOT/cache/huggingface" \
  "$ASSETS_ROOT/cache/npm" \
  "$ASSETS_ROOT/cache/pip"

printf 'Initialized LLM security assets at %s\n' "$ASSETS_ROOT"
