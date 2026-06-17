@echo off
setlocal
wsl.exe -e bash -lc "cd /mnt/d/vscodefile/llm-security-guardrail-platform/backend && . .venv_server/bin/activate && exec python -m uvicorn app.api.main:app --host 0.0.0.0 --port 8000"
