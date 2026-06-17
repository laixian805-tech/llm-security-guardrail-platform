# Implementation Notes

## Current Slice

The first backend slice is intentionally small and testable. It provides the contracts that later RAG, agent, evaluation, and dashboard modules will rely on:

- `GuardResult` records guardrail stage, rule name, action, confidence, and metadata.
- `ToolCallVerdict` records tool tier, argument validation, permission checks, and final decision.
- `SessionSecurityReport` derives session-level counts from auditable agent steps.
- `EvalRun` derives a summary from attack results when one is not provided.
- `ModelProvider` keeps `/chat` and `/v1/chat/completions` on the same guarded generation path.
- `PersistentHybridRAGService` stores chunks in JSON under the WSL asset directory and produces explainable hybrid retrieval scores.
- `LocalEvalRunner` runs built-in attack probes and writes JSON, CSV, and HTML artifacts for dashboard/report consumption.
- `GarakEvalRunner` shells out to Garak, targets the same OpenAI-compatible endpoint, and normalizes Garak reports into the local `EvalRun` schema.

## Design Defaults

- Guardrail mode defaults to `enforce`.
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
- Garak now targets the shared OpenAI-compatible API layer and reuses the local report API shape
- Promptfoo should target the same OpenAI-compatible API layer next
