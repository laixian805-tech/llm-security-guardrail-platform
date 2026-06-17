# AutoDL Agent Prompt

Use this prompt for any AI agent that continues deployment, evaluation, or debugging work on this project.

## Role

You are maintaining an LLM security guardrail platform where Tencent Cloud is the lightweight platform entrypoint and AutoDL is the GPU compute backend.

Do not assume Tencent Cloud can run real model inference locally. Tencent Cloud should run only:

- FastAPI backend and static frontend on port `8000`
- project source and reports
- SSH tunnel to AutoDL on local port `18000`

AutoDL should run:

- Qwen3-8B vLLM OpenAI-compatible API on `127.0.0.1:8000`
- Garak runner environment
- long or real security benchmarks

## First Checks Before Any Real Evaluation

Before running `/experiments/formal-run`, Garak, Promptfoo, or any real qwen3 test, always run this on Tencent Cloud:

```bash
cd /root/llm-security-guardrail-platform
bash scripts/check-autodl-recovery.sh
```

If vLLM is down but AutoDL is reachable:

```bash
bash scripts/check-autodl-recovery.sh --start-vllm
```

If AutoDL is unreachable, do not reinstall anything. First ask whether the AutoDL instance is powered on and whether the SSH host/port changed.

## Required Facts

- AutoDL SSH default: `ssh -p 16214 root@region-9.autodl.pro`
- AutoDL persistent disk: `/root/autodl-tmp`
- Model cache: `/root/autodl-tmp/hf/hub/models--Qwen--Qwen3-8B`
- Garak runner: `/root/autodl-tmp/llmsec-runner/.venv_eval_system`
- vLLM launcher: `/root/autodl-tmp/bin/start-vllm-qwen3.sh`
- Tencent tunnel: `127.0.0.1:18000 -> AutoDL 127.0.0.1:8000`
- Backend health: `curl http://127.0.0.1:8000/health`
- AutoDL model health through tunnel: `curl http://127.0.0.1:18000/v1/models`

## Important Implementation Details

The current AutoDL GPU is Tesla V100S. vLLM must start Qwen3-8B with:

```bash
--dtype half
```

Do not remove it. V100S does not support bf16. Without `--dtype half`, vLLM fails with a bfloat16 compute capability error.

The backend OpenAI-compatible endpoint supports `max_tokens` and `temperature`. Use low `max_tokens` for smoke tests so Qwen3 reasoning does not make tests appear stuck.

## What To Avoid

- Do not redownload Qwen3-8B unless `/root/autodl-tmp/hf/hub/models--Qwen--Qwen3-8B` is missing.
- Do not reinstall Garak unless `/root/autodl-tmp/llmsec-runner/.venv_eval_system/bin/python -c "import garak"` fails.
- Do not run full Garak promptinject casually from Tencent Cloud. Use AutoDL and narrow probes first.
- Do not treat `Connection reset by peer` as an application bug before checking AutoDL vLLM and the tunnel.
- Do not leave manual uvicorn processes occupying Tencent port `8000`; it must be owned by `system.slice/llmsec-backend.service`.

## Shutdown Handoff

Before shutting down AutoDL, run:

```bash
cd /root/llm-security-guardrail-platform
bash scripts/sync-autodl-compute-assets.sh --check-only
```

This confirms model cache, runner environment, reports, and launcher live on `/root/autodl-tmp`. Running jobs will not survive shutdown, but these assets should.

After AutoDL restarts, run:

```bash
cd /root/llm-security-guardrail-platform
bash scripts/check-autodl-recovery.sh --start-vllm
```

Then run only a small smoke test before any long benchmark.

