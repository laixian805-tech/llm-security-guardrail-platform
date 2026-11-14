# 2026-11-14 P2 验收报告 · 非环境变量谱系推导、实时推送/PG对等、系统采集扩展与外部基准评测

> 对应分支 `asgp`。所有实测数据均附执行环境与适用边界，遵守「实证口径隔离」与「基线同步」约束。

## 1. P2-1：非环境变量 `SourceKind` 谱系自动推导

- **新增模块**：`endpoint/lineage.py`（纯标准库，接入 `endpoint/hook.py`）。
- **核心逻辑**：`infer_lineage(product, payload, tool_call_id=...)` 仅在显式 `ASGP_SOURCE_KIND` 存在时作为受控实验标签；否则对 `transcript_path` 执行有界只读尾部解析（最大 256 KiB），支持 Claude Code / Qwen Code / Codex 三款产品的 JSONL 格式，按最近真实用户指令之后是否经过 `tool_result`、工作区规则文件（`CLAUDE.md`/`AGENTS.md`/`.mcp.json`）、`Skill` 或 `mcp__*` 工具来推导 `(source_kind, source_ref)`，绝不外传对话正文或凭据。
- **Host b 真机 `.jsonl` 实测（不设置 `ASGP_SOURCE_KIND`）**：
  - Claude Code 真实会话 `017a8082...jsonl`：`('user_task', 'transcript:claude-code:user_turn')`，耗时 `1.11 ms`；
  - Qwen Code 真实会话 `6eaf7e67...jsonl`：`('tool_output', 'tool_output:read_file')`，耗时 `4.56 ms`；
  - Codex 真实会话 `rollout-...1397.jsonl`：`('user_task', 'transcript:codex:user_turn')`，耗时 `1.42 ms`。

## 2. P2-2：PostgreSQL Schema 对等校验、实时推送（SSE/长轮询/Webhook）与异步入库

- **PostgreSQL 双引擎与对等校验**：新增 `backend/storage/postgres_adapter.py`，基于 `SQLAlchemy 2.1.8` 提供 `generate_postgres_ddl()` 与 `create_sqlalchemy_engine()`（若环境中缺少 `psycopg`/`psycopg2` 驱动则 fail-closed 显式抛 `postgres_driver_missing`，绝不静默降级）。
  - **Host a 本机 PostgreSQL 实测验证**：将生成的 DDL 导入临时库 `asgp_pg_schema_check` 执行通过，对比 SQLite v12 迁移库实现 **`29/29` 张表、`295/295` 列、`schema_version = 12` 严格对等**（验证后已清理临时库）。
- **实时通知与异步入库**：
  - 新增 `backend/services/notification_hub.py`（进程内 Pub/Sub、`wait_approval` 条件唤醒、防 SSRF 的 HMAC-SHA256 可选 Webhook）并接入 `ApprovalService`。
  - 新增 `GET /api/v1/events/stream`（`Permission.READ`，Server-Sent Events，支持 `?once=1`）与 `GET /api/v1/approval-requests/{id}?wait=1&timeout=...`（接入 `endpoint/approval.py` 长轮询唤醒）。
  - 新增 `backend/services/async_ingestion.py` 与 `POST /api/v1/runtime-events:ingest-async`（同步完成设备与参数合法性校验后返回 HTTP `202 Accepted` 并异步落库，队满返回 `429` 背压）。
  - `/api/health` 新增 `storage_dialect`、`async_ingest`、`sse_subscribers` 健康状态字段。

## 3. P2-3：端侧 `sendto`/`sendmsg` + LOTS 覆盖与 `coverage_reports` 闭环修复

- **`endpoint/audit.py` & Host b 审计规则**：扩展 x86_64 系统调用映射捕获 `44 (sendto)` 与 `46 (sendmsg)`（仅当解析到合法 IPv4/IPv6 `SOCKADDR` 时上报，无 `SOCKADDR` 的本地/已连接 IPC 套接字直接忽略避免噪声）；Host b `augenrules --load` 生效，实时发出测试 UDP 包至 RFC 5737 TEST-NET `203.0.113.53:53` 后在 Host a `fusion.db` 验收到 `('audit_fd98964becb2031a7568714c17153f35', 'sendto', '203.0.113.53', 53)`。
- **LOTS 临时外带识别**：`backend/services/evidence_rules.py` 新增 `LOTS_ABUSE_DOMAINS` 与 `is_lots_endpoint()`（识别 `webhook.site`、`pipedream.net`、`trycloudflare.com`、`transfer.sh`、`paste.ee`、`api.telegram.org` 等），并在 `EffectDiffService` 给出显式 LOTS 原因标注。
- **端云覆蓋度对账闭环修复（历史静默 400/500 Bug 根除）**：排查发现 `coverage_service.py` 拒收 `endpoint/coverage.py` 附带的 `dropped_records`/`unbounded_gaps`（HTTP 400），且 `data/fusion.db` 旧库升级到 v12 后 `coverage_reports` 缺 `delivered` 列（HTTP 500）。已在 `coverage_service.py` 与 `schema.py`（`_ensure_coverage_delivered` 幂等迁移）修复后重启服务，Host b 已连续实时写入多条 `POST /api/v1/coverage-reports`（HTTP `200`，`fusion.db` 实库已有真实上报行，`backlog=28, dead=0`）。

## 4. P2-4：AgentDojo / InjecAgent 风格外部基准与 Wilson 95% 置信区间评测

- 新增 `scripts/lab/eval_stats.py`（零外部依赖 `wilson_ci`）与 `scripts/lab/eval_external_benchmarks.py`，输出至 `docs/acceptance/external-benchmark-eval.json`。
- **样本构成（`N = 40`）**：`20` 例 AgentDojo 风格（12 间接提示注入 + 8 多回合工作区良性工具流） + `20` 例 InjecAgent 风格（12 工具响应劫持 + 8 良性工具流）；全量通过 `infer_lineage`（40/40 无环境变量推导）→ `IngestionService` → `AttributionService` → `EffectDiffService` + `DataFlowService` 执行，并附 Wilson 95% 置信区间：

| 基线模型 | Precision | Recall (Wilson 95% CI) | F1 | FPR (Wilson 95% CI) |
| --- | --- | --- | --- | --- |
| `M0_static_only` | `1.0000` | `0.1667` (`[0.0668, 0.3585]`) | `0.2857` | `0.0000` (`[0.0000, 0.1936]`) |
| `M1_hook_only` | `1.0000` | `0.0417` (`[0.0074, 0.2024]`) | `0.0800` | `0.0000` (`[0.0000, 0.1936]`) |
| `M2_regex_dlp` | `0.3333` | `0.0833` (`[0.0232, 0.2585]`) | `0.1333` | `0.2500` (`[0.1018, 0.4950]`) |
| `M4_full_asgp` | `1.0000` | `1.0000` (`[0.8620, 1.0000]`) | `1.0000` | `0.0000` (`[0.0000, 0.1936]`) |

- **诚实边界**：本基准属于基于 AgentDojo / InjecAgent 任务原型构造的离线确定性轨迹套件（`deterministic_offline_agentdojo_injecagent_archetype_suite`），用于严格对照跨层机制能力与给出 95% 置信区间，**不宣称为实时在线 LLM 权重全集测试结果**。

## 5. 全量自动化验证与 Host b 资源状态

- `./scripts/test.sh`：`scan_hardcoded.py` 扫描 `86` 个代码文件、`37` 个测试文件 `0` 问题；`pytest` 全量 **`489 passed in 142.85s (0:02:22)`**。
- `scripts/export-schemas.py --check` 退出码 `0`。
- Host b（2C2G，`Swap: 0`）：`Mem: 1736 MiB total / 407 used / 1154 available`，`asgp-audit-collector`（`MemoryCurrent=12267520` ~`11.7 MiB`）与 `asgp-endpoint-flush`（`MemoryCurrent=12013568` ~`11.5 MiB`）均远低于 `96M` 配额；`auditctl -s` 内核 `lost=0, backlog=0`。
## 6. 防误报与灰度发布补充（Shadow Deny + 定向灰度 `PolicyRule`）

- **端侧非阻断干跑（Shadow Deny）**：`endpoint/hook.py`（`_eval_shadow_patterns`）与 `endpoint/redaction.py`（`summarize(..., shadow_matches=...)`）支持 `shadow_deny_patterns` 配置；命中时在 `observe` 与 `deny` 模式下均**不阻断正常业务执行**，仅随摘要上报脱敏指标 `shadow_would_block: true` 与 `shadow_matches: [{rule_id, pattern_sha256}]`（截断至 8 项，不回传原始参数或正则文本）。
- **控制面定向灰度与只审计影子策略**：`backend/domain/governance.py`（`PolicyRule`）及 `contracts/policy-version.schema.json` 新增可选字段 `target_host_ids`（`max_length=64`）、`target_products`（`max_length=16`）与 `shadow_only: bool = False`。`PolicyService.evaluate(..., host_id=..., product=...)` 与 `GovernanceService.evaluate(body)` 在未命中灰度白名单时自动跳过规则；命中 `shadow_only=True` 规则时强制降级为 `PolicyAction.AUDIT` 并标记 `[SHADOW would={action}]`。
- **误报观测聚合接口**：新增 `GET /api/v1/policies/shadow-summary`（`Permission.READ`），参数化聚合控制面 `[SHADOW would=...]` 决策与端侧 `intents` `shadow_would_block` 命中数。
- **验证与诚实边界**：
  - 单元测试与 API 测试见 `tests/test_p2_shadow_canary.py`（包含在 `./scripts/test.sh` 的 `489 passed in 142.85s` 中）。
  - 主机 b 端侧冒烟实测：`{'directive': '', 'decision': 'not_applicable', 'shadow_would_block': True, 'shadow_matches': [{'pattern_sha256': 'dc86dcaf7ed3', 'rule_id': 'shadow-test'}]}`。
  - **诚实边界**：当前实验环境仅包含单台控制面（主机 a）与单台端侧实验机（主机 b，2C2G），以上验证证明单端侧与多设备/多产品模型测试下规则作用域过滤、非阻断上报与回滚逻辑成立；百台以上生产集群的分批次百分比下发效果尚待企业多节点环境实测。
