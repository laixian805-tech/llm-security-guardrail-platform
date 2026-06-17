# AutoDL Recovery Runbook

Tencent Cloud is the platform entrypoint. AutoDL is the compute backend.

Current split:

- Tencent project root: `/root/llm-security-guardrail-platform`
- Tencent backend service: `llmsec-backend.service`
- Tencent public entrypoint: `http://43.139.77.64:8000`
- Tencent local AutoDL tunnel: `127.0.0.1:18000 -> AutoDL 127.0.0.1:8000`
- AutoDL persistent root: `/root/autodl-tmp`
- AutoDL model cache: `/root/autodl-tmp/hf`
- AutoDL eval runner: `/root/autodl-tmp/llmsec-runner`
- AutoDL vLLM launcher: `/root/autodl-tmp/bin/start-vllm-qwen3.sh`

## Current Sync Status

The compute side is already on AutoDL. Tencent Cloud should only run the platform itself.

AutoDL already contains:

- Qwen3-8B model cache under `/root/autodl-tmp/hf`
- vLLM runtime from the AutoDL Python environment
- Garak eval runner under `/root/autodl-tmp/llmsec-runner`
- AutoDL-side reports under `/root/autodl-tmp/llmsec-runner/reports`
- vLLM launcher under `/root/autodl-tmp/bin/start-vllm-qwen3.sh`

Tencent Cloud contains:

- Project source, backend, frontend static files
- FastAPI/systemd platform entrypoint on port `8000`
- Report storage under `/root/llmsec-assets`
- SSH tunnel to AutoDL on local port `18000`

Tencent Cloud should not redownload Qwen3-8B or run local model inference.

## What Persists After AutoDL Shutdown

AutoDL container processes do not persist after shutdown. The vLLM process and any running Garak job will stop.

The important assets should persist on `/root/autodl-tmp`:

- Qwen3-8B model cache: `/root/autodl-tmp/hf/hub/models--Qwen--Qwen3-8B`
- Garak runner venv: `/root/autodl-tmp/llmsec-runner/.venv_eval_system`
- Runner scripts: `/root/autodl-tmp/llmsec-runner/scripts`
- vLLM start script: `/root/autodl-tmp/bin/start-vllm-qwen3.sh`
- Reports: `/root/autodl-tmp/llmsec-runner/reports`

So a normal AutoDL restart should not require reinstalling Garak or redownloading Qwen3-8B. It should only require reconnecting SSH/tunnel and starting vLLM.

## Normal Recovery

Run this from Tencent Cloud:

```bash
cd /root/llm-security-guardrail-platform
bash scripts/check-autodl-recovery.sh
```

This command tells you whether AutoDL is unreachable, whether the persistent assets are missing, whether vLLM is down, or whether the Tencent tunnel is broken.

If AutoDL is reachable but vLLM is down:

```bash
bash scripts/check-autodl-recovery.sh --start-vllm
```

Then verify the platform:

```bash
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:18000/v1/models
curl http://43.139.77.64:8000/
```

## If AutoDL Cannot Be Reached

If SSH fails, first check whether the AutoDL instance is powered on and whether the SSH port is still:

```bash
ssh -p 16214 root@region-9.autodl.pro
```

If AutoDL assigned a new host or port, update these when running the check:

```bash
LLMSEC_AUTODL_HOST=<new-host> \
LLMSEC_AUTODL_PORT=<new-port> \
bash scripts/check-autodl-recovery.sh --start-vllm
```

If the SSH target changed permanently, update the Tencent tunnel command or service to use the new host and port.

## Expected Healthy State

Tencent:

- `llmsec-backend.service` is `active`
- `0.0.0.0:8000` is owned by `system.slice/llmsec-backend.service`
- `127.0.0.1:18000` is listening as an SSH local forward
- `/health` shows `model_provider=autodl`, `model_name=qwen3:8b`

AutoDL:

- `/root/autodl-tmp/hf/hub/models--Qwen--Qwen3-8B` exists
- `/root/autodl-tmp/llmsec-runner/.venv_eval_system` exists
- `python -m garak` imports successfully
- vLLM serves `http://127.0.0.1:8000/v1/models`
- vLLM is started with `--dtype half` on V100S; default bf16 will fail

## Why `--dtype half` Is Required

The current AutoDL GPU is Tesla V100S with compute capability 7.0. Qwen3-8B defaults to bfloat16 in vLLM, but V100S does not support bf16. The launcher must include:

```bash
--dtype half
```

Without it, vLLM fails with:

```text
Bfloat16 is only supported on GPUs with compute capability of at least 8.0
```

## Current Validation

Last known successful validation:

- AutoDL vLLM started with Qwen3-8B
- Tencent `/v1/chat/completions` reached real qwen3:8b through the SSH tunnel
- `max_tokens` forwarding was fixed and tested
- AutoDL Garak smoke completed:
  `/root/autodl-tmp/llmsec-runner/reports/garak-autodl-smoke-20260617-115648`

## Do Not Reinstall Unless These Are Missing

Do not reinstall Garak or redownload Qwen unless these checks fail:

```bash
test -d /root/autodl-tmp/hf/hub/models--Qwen--Qwen3-8B
test -x /root/autodl-tmp/llmsec-runner/.venv_eval_system/bin/python
/root/autodl-tmp/llmsec-runner/.venv_eval_system/bin/python -c "import garak, torch"
```
