# Agent Instructions

This repository is deployed as a split Tencent Cloud + AutoDL system. Before changing deployment, inference, benchmark, recovery, or production operations, read:

- `AUTODL_AGENT_PROMPT.md`
- `AUTODL_RECOVERY.md`

## Current Production Shape

- Tencent Cloud is the lightweight platform entrypoint.
- Tencent Cloud runs FastAPI, the static frontend, reports, and orchestration on public port `8000`.
- Tencent Cloud must not run local Qwen/Ollama inference.
- AutoDL is the GPU compute backend.
- AutoDL runs Qwen3-8B through vLLM on `127.0.0.1:8000`.
- Tencent reaches AutoDL through the local tunnel `127.0.0.1:18000 -> AutoDL 127.0.0.1:8000`.

## First Check For Real Model Work

Before running real qwen3 tests, formal experiments, Garak, Promptfoo, or debugging model failures, run this on Tencent Cloud:

```bash
cd /root/llm-security-guardrail-platform
bash scripts/check-autodl-recovery.sh
```

If AutoDL is reachable but vLLM is down:

```bash
bash scripts/check-autodl-recovery.sh --start-vllm
```

If AutoDL is unreachable, do not reinstall or redownload first. Check whether the AutoDL instance is powered on and whether the SSH host or port changed.

## AutoDL Shutdown And Restart

Before shutting down AutoDL, verify that persistent compute assets are on `/root/autodl-tmp`:

```bash
bash scripts/sync-autodl-compute-assets.sh --check-only
```

AutoDL shutdown stops running processes, but `/root/autodl-tmp` should keep the Qwen3-8B model cache, Garak runner, vLLM launcher, and reports. After restart, use `scripts/check-autodl-recovery.sh --start-vllm` instead of reinstalling.

For clean shutdown previews, run `bash scripts/stop-autodl-compute.sh`. Only run `bash scripts/stop-autodl-compute.sh --apply` when the user intentionally wants to stop AutoDL compute processes.

## Working Rules

- **No commits without explicit permission**: never run `git commit` or `git push` (local or remote) unless the user explicitly says so in the current conversation. Leave changes in the working tree, tell the user they are uncommitted, and stop to ask first.
- **No secrets in the repo**: API keys, tokens, and credentials must never be committed or pushed. Store them in environment variables or gitignored local files (e.g. `.agentsec.local.env`); verify `.gitignore` coverage before any commit. Keys must never appear in logs, reports, or uploaded events.
- **No minimal-MVP delivery**: deliver complete, working, validated results. Do not hand off stubs, TODOs, or half-finished features as "done"; if scope must shrink, state it explicitly and confirm with the user first.
