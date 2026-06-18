# Implementation Notes

## Current Slice

The first backend slice is intentionally small and testable. It provides the contracts that later RAG, agent, evaluation, and dashboard modules will rely on:

- `GuardResult` records guardrail stage, rule name, action, confidence, and metadata.
- `GuardrailPipeline` defaults to NeMo Guardrails runtime first and records runtime/fallback metadata while preserving the existing `GuardResult` contract.
- `ToolCallVerdict` records tool tier, argument validation, permission checks, and final decision.
- `SessionSecurityReport` derives session-level counts from auditable agent steps.
- `EvalRun` derives a summary from attack results when one is not provided.
- `ModelProvider` keeps `/chat` and `/v1/chat/completions` on the same guarded generation path.
- `PersistentHybridRAGService` stores chunks in JSON under the WSL asset directory and produces explainable hybrid retrieval scores.
- `LocalEvalRunner` runs built-in attack probes and writes JSON, CSV, and HTML artifacts for dashboard/report consumption.
- `GarakEvalRunner` shells out to Garak, targets the same OpenAI-compatible endpoint, and normalizes Garak reports into the local `EvalRun` schema.

## Design Defaults

- Guardrail mode defaults to `enforce`.
- Guard engine defaults to `nemo`; NeMo Guardrails is a normal backend dependency, not a future optional integration.
- `GuardMode.OFF` bypasses NeMo/custom checks completely so baseline experiments measure raw model behavior.
- NeMo runtime runs in the Tencent Cloud backend process. Deterministic rails run locally inside NeMo, and NeMo self-check rails use the existing OpenAI-compatible model endpoint. AutoDL remains the vLLM/GPU compute backend.
- Qwen OpenAI-compatible calls pass `chat_template_kwargs.enable_thinking=false`; provider output still strips `<think>` blocks as a final safety net.
- Runtime assets default to `/home/tlx/llmsec-assets`.
- The model provider defaults to `stub` so development does not require a local model.
- The default local model is `qwen3:8b` behind Ollama.
- The initial tool catalog includes `search_kb`, `calculator`, `policy_lookup`, `report_lookup`, `user_info`, and `export_data`.
- The current RAG implementation is persistent, role-aware, and blocks bulk dump queries before retrieval.
- The evaluation adapters are `local` and `garak`; Promptfoo should normalize into the same `EvalRun` and `AttackResult` schemas next.

## Evaluation Direction

The project is following the evaluation-complete direction:

- guardrail actions are structured and attributable
- tool abuse is traceable to tier checks or argument policy checks
- RAG security exposes audit records and hybrid retrieval score components now; Chroma collections are the next storage upgrade
- Garak now targets the shared OpenAI-compatible API layer and reuses the local report API shape.
- Promptfoo targets the same OpenAI-compatible API layer and writes normalized report artifacts.
- NeMo Guardrails is now the primary guardrail framework, while RAG sanitizer, ToolGateway, and dynamic guard packs remain deterministic boundaries around the model.
- RAG sanitizer isolates low-trust imperative chunks before invoking model-backed guardrails, which avoids unnecessary self-check latency and keeps source isolation deterministic.

## NeMo Guardrails Upgrade Path

NeMo is treated as the explainable guardrail framework, not as a replacement for platform boundaries.

- `/guardrails/nemo-pack` exposes the active NeMo config as a defense pack: config path, rail flows, prompt summaries, blocked intents, runtime status, and fallback policy.
- RAG retrieval still returns all chunks for audit, but only sanitized trusted chunks enter Agent context. Low-trust, poisoned, or isolated chunks remain audit-only with isolation metadata.
- Tool calls now pass through a tool-intent guardrail check before `ToolGateway`; `ToolGateway` remains the deterministic permission boundary.
- Failure feedback remains a loop: failed samples -> `/experiments/defense-suggestions` -> candidate rules and `next_round_payloads` -> `/experiments/regression-preview` -> `/experiments/security-cycle`.
- NeMo vs custom comparisons should run the same probe set against `guard_engine=custom_nemo` and `guard_engine=nemo`, then compare ASR, average latency, fallback usage, and rule-hit distribution in the generated reports.

## Mature Closed Loop Additions

The closed loop now has explicit review and regression artifacts:

- Guard Pack approval: `/guard-packs/approve-activate` records `approved_by`, `approval_note`, `approved_at`, activates the reviewed pack, and can immediately run a regression preview against supplied payloads.
- Benign false-positive gate: `/experiments/benign-preview` runs normal business prompts through the active guardrails without invoking the model and reports `false_positive_rate`.
- Regression set versioning: `/experiments/regression-sets` stores named, versioned payload sets such as `coverage-v1`, so failed samples can become stable regression assets instead of loose JSON snippets.
- RAG collection management: `/rag/collections` lists document/chunk counts, source types, trust levels, and poison labels; `DELETE /rag/collections/{collection}` removes a collection from the persistent RAG store.
- Tool policy hardening: `ToolGateway` enforces manifest-level type, enum, length, and numeric constraints before role-tier authorization.

Latest real AutoDL validation:

- `qwen3:8b` six-probe security-cycle: `eval-673bef03` -> `eval-ac05b1e2`, 6 attacks, baseline ASR 100%, guarded ASR 0%, graph `security_cycle-194382c9`.
- Coverage regression expansion: saved 12 paraphrase, multi-turn, translated, RAG/web, tool-output, and unauthorized-tool variants as `coverage-expansion-v1`.
- `qwen3:8b` six-probe plus regression security-cycle: `eval-dccb53e1` -> `eval-1d9e13c8`, 18 attacks, baseline ASR 100%, guarded ASR 0%, graph `security_cycle-bd6dcb41`.
- `mistral-7b` six-probe plus the same regression set: `eval-a0c2ac0c` -> `eval-caeb761f`, 18 attacks, baseline ASR 100%, guarded ASR 0%, graph `security_cycle-ff5297e5`.
- Rule-hit distribution in both 18-sample runs was `llmsec_deterministic_input_check=7` and `self_check_input=11`, so NeMo deterministic rails and model-backed self-check both contributed.
- Benign false-positive gate with 12 normal business/security prompts returned `false_positive_rate=0.0`.
- NeMo runtime config is materialized per active evaluation model, so Mistral self-check rails call `mistral-7b` instead of the default Qwen config.
- When guarded failures are zero, the next defense iteration should expand coverage breadth rather than tune a new rule from nonexistent failure samples.

Recommended mature workflow:

1. Run `security-cycle` and inspect failed samples, rule hits, Graph Run, and defense suggestions.
2. Create or review candidate rules, then activate with `/guard-packs/approve-activate`.
3. Run `/experiments/benign-preview` to make sure normal prompts are not over-blocked.
4. Save failed or generated payloads with `/experiments/regression-sets`.
5. Re-run `/experiments/security-cycle` with regression payloads and compare reports.
