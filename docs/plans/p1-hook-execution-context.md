> **2026-11-11 执行更新**：用户已明确授权在 `116.62.28.177` 接入 Codex 和 Claude，并提供测试机访问方式。S1–S7 主链路现已实现，真实产品/队列/供应商与回滚证据见 [验收报告](../acceptance/2026-11-11-p1.md)。Codex 0.166.0 的 Hook ask 被实测为忽略，无法实现产品原生确认；当前明确 unsupported，需确认规则改为拒绝。下文为原计划历史，不代表各项原始假设均成立。

> 接手归档说明（2026-11-11）：下文保存 Claude 已获批准的完整 P1 计划，原始来源为 `/root/.claude/plans/atomic-singing-island.md`。本次仅增加说明，原计划正文保持原样。当前实现状态与核验结果见 [项目接手梳理](../project-handover.zh-CN.md)。
>
> **后续用户要求优先：真实 Hook 安装/验证只在测试机进行，不在本机开发环境安装。** 这一要求晚于下文的本机安装步骤。S1/S2 已获准按四条提交，但接手时仍未提交；S3 仅有录制脚本，S4–S7 尚未实现。当前 Claude Code 能力仍为 `unverified`，Codex 不能摄入事件；文中 `verified`、`endpoint/`、摄入 API 等描述均须结合实际交付状态理解。
>
> 本计划是执行依据，不是验收报告。代码撤回与数据库回滚需分别验证，性能描述需补实测。

# P1：多产品接入与 Hook 执行上下文 — 实施计划

## Context

ASGP 控制面（`/root/agent-security-fusion-platform`）P0 已完成：领域契约、检测器集成、控制台认证、设备注册、审计与保留策略全部落地（146 passed / 7 skipped）。但平台目前只能观测「扫描」，不能观测「Agent 怎么做」——没有 Execution/Intent 概念，拿不到 Claude Code / Codex 的执行上下文，策略判断无处附着。

P1 要打通这条链路：产品 Hook 观测执行上下文 → 端侧脱敏 + 持久 outbox → 设备认证上报 → 控制面落库 → timeline 查询。`IMPLEMENTATION_PLAN.md:26-41` 定义的范围与四条验收（下称 A1-A4）是本计划的验收基准：

- **A1** 每个支持版本的 Hook fixture 有 allow/confirm/block 三类协议测试和字段兼容测试
- **A2** 一个真实或可复现的 Codex/Claude 执行能关联到 Execution 和 Intent；重复上报幂等
- **A3** Hook 服务离线时按产品能力策略降级；未验证行为标注为未验证，不宣称已拦截
- **A4** 端点不上传原始 prompt、完整密钥参数或环境变量；日志有 request/event ID 但不含秘密

**范围决策（用户已确认）**：① 全量 P1，分切片排序，每片可独立部署/验证/回滚；② Claude Code 与 Codex 适配器都做，Codex 能力标注「未验证」；③ 端侧组件放在控制面仓库内 `endpoint/` 目录；④ S5 最小 web UI 纳入 P1（限界版）；⑤ 真实 Claude Code 协议尖峰放在 S2 之后、摄入链路之前。

**硬约束（贯穿所有切片）**：

1. 新 Pydantic 契约模型必须同步进 `scripts/export-schemas.py` 的 `SCHEMAS` 并重新生成 `contracts/*.schema.json`，否则 `tests/test_contract_sync.py` 双向失败。
2. 服务端覆盖客户端提交的 host 身份字段（`API_CONTRACT.md` §6）——防伪造的必需件。
3. prompt 正文、`tool_input` 原文、环境变量、`transcript_path` 不得进入任何契约表。
4. 未实现/未验证能力在 API 与 UI 上必须显式标注，不得用空数组蒙混。
5. 设备身份与控制台用户身份不互替（`backend/services/auth_service.py:1-8` 的既有边界）。
6. P1 全部工作只在控制面仓库；`/root/asgp-v1`（A.I.G fork）不引用、不修改。

---

## 切片总览

| 切片 | 主题 | 独立验证 | 独立回滚 |
|---|---|---|---|
| S1 | Execution/Intent/RuntimeEvent 契约 + JSON Schema + v5 存储 + repo + 保留策略 | `pytest tests/test_domain_contracts.py tests/test_storage_migration.py tests/test_execution_repositories.py` | 迁移纯增量，revert 即净身 |
| S2 | AgentProductAdapter 框架 + Claude Code/Codex 适配器 + 能力矩阵 + ADR 0006 + 协议文档 | `pytest tests/test_product_adapters.py tests/test_contract_sync.py` | 纯代码+文档，revert 即净身 |
| S3 | **真实 Claude Code 协议尖峰**：录制 hook → 与适配器比对 → 提升为 fixture → 修正 S2 | 尖峰报告 + fixture 测试全绿 | 卸载录制 hook，settings.json 还原备份 |
| S4 | 设备认证 `/api/v1` 上报端点 + host 绑定 + token 轮换 + ActorKind.DEVICE 审计 + secret 闸门 | `pytest tests/test_v1_ingest.py tests/test_console_auth.py` | `ASGP_V1_ENABLED=0` 一键断流，或 revert |
| S5 | `endpoint/` 端侧包：hook 接收、本地脱敏、持久 outbox、批量上报器、安装器 | `pytest tests/test_endpoint_*.py`（含 drift 守卫，不依赖 S4 已上线） | `--uninstall` + 删 `~/.asgp/endpoint`，控制面无感 |
| S6 | timeline 查询 API + 最小 web UI（限界版） | `pytest tests/test_timeline_api.py` + 页面手工核对 | 只读 API + 静态页，revert 即消失 |
| S7 | E2E 脚本 + runbook + 文档收口 + P1 验收证据 | `scripts/e2e-hook-timeline.sh` + 联调证据 | 无产品代码，卸载 hook 即回滚 |

**为什么尖峰（S3）插在 S2 后**：S4/S5 的摄入链和端侧包都建立在「适配器解析的字段与真实 Claude Code hook payload 一致」这个假设上。若假设错了，返工成本最高。尖峰用一次真实会话把假设变成事实，再让后续切片施工。S1/S2 本身不依赖真实产品，可先合入保持绿灯。

**为什么 S5/S6 的边界这样切**：S5 交付端侧（可被假服务端驱动的代码），S6 交付控制面读侧与 UI，S7 才做真实联调。UI 是 S6 最后一个提交，可单独 revert 到 P2。

---

## S1 — Execution/Intent/RuntimeEvent 契约与存储

**目标**：把 `DATA_MODEL.md` 的三个实体落成 Pydantic 契约 + SQLite 表 + repo，并同时落地保留策略（hook 每个工具调用都写库，无保留策略是最可能的生产事故）。

**新增文件**

- `backend/domain/execution.py` — `Execution`、`Intent` 契约；校验器：非执行前 hook 事件不得携带 decision；`outcome=running` 不得有 `ended_at`，终态必须有
- `backend/domain/runtime_event.py` — `RuntimeEvent`、`ProcessInfo`、`ResourceInfo` 契约；`intent_ref` 注释为采集器提示而非外键
- `backend/storage/execution_repositories.py` — `ExecutionRepository` / `IntentRepository` / `RuntimeEventRepository`（与 `repositories.py` 分开：该文件已 708 行且本批表与扫描域无关，独立文件可整文件回滚）
- `tests/test_execution_repositories.py`
- `contracts/execution.schema.json`、`intent.schema.json`、`runtime-event.schema.json`、`process-info.schema.json`、`resource-info.schema.json`（脚本生成）

**修改文件**

- `backend/domain/enums.py` — 新增 `ExecutionOutcome`（unknown/running/completed/aborted/failed）、`IntentDecision`（not_applicable/allow/ask/deny）、`HookEventType`（session_start/pre_tool_use/post_tool_use/session_end/synthetic）、`PRE_EXECUTION_HOOK_EVENTS` 常量；`RetentionKind` 增加 `EXECUTIONS`、`RUNTIME_EVENTS`
- `backend/domain/__init__.py` — 导出新模型与枚举
- `backend/storage/schema.py` — `SCHEMA_VERSION = 5`；DDL 追加三张表 + `device_identities` 两列（`host_id`、`credential_rotated_at`）；`INDEX_DDL` 追加索引；新增 `_migrate_v5()`
- `scripts/export-schemas.py` — `SCHEMAS` 增加 5 个映射
- `backend/storage/repositories.py` — `DEFAULT_RETENTION_DAYS` 增加两项；`RetentionRepository.prune()` 增加两段删除逻辑
- `tests/test_domain_contracts.py`、`tests/test_storage_migration.py` — 追加用例

**DDL 设计**（遵循 `schema.py:18-157` 现有注释密度与约束风格）

```sql
CREATE TABLE IF NOT EXISTS executions (
    execution_id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL,
    device_id TEXT NOT NULL REFERENCES device_identities(device_id),
    product TEXT NOT NULL,
    product_version TEXT NOT NULL,
    session_id TEXT NOT NULL,
    asset_instance_id TEXT,          -- P1 无资产注册表，只存客户端引用，不做存在性校验
    started_at TEXT NOT NULL,
    ended_at TEXT,
    outcome TEXT NOT NULL,
    intent_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (host_id, product, session_id)
);
CREATE INDEX executions_host_time ON executions(host_id, started_at);
CREATE INDEX executions_session ON executions(session_id);

CREATE TABLE IF NOT EXISTS intents (
    intent_id TEXT PRIMARY KEY,
    execution_id TEXT NOT NULL REFERENCES executions(execution_id) ON DELETE CASCADE,
    parent_intent_id TEXT REFERENCES intents(intent_id),   -- P1 恒 NULL，为 P2 子 Agent 预留
    tool_call_id TEXT,
    tool_name TEXT NOT NULL,
    hook_event_type TEXT NOT NULL,
    decision TEXT NOT NULL,
    decision_reason TEXT,
    params_summary TEXT NOT NULL DEFAULT '',   -- 端侧脱敏后的摘要，≤8192 字符
    params_sha256 TEXT,
    redaction_applied INTEGER NOT NULL DEFAULT 0,
    occurred_at TEXT NOT NULL,
    ended_at TEXT,
    product_result TEXT,
    created_at TEXT NOT NULL,
    UNIQUE (execution_id, tool_call_id)
);
CREATE INDEX intents_execution_time ON intents(execution_id, occurred_at);
CREATE INDEX intents_tool_call ON intents(tool_call_id);

CREATE TABLE IF NOT EXISTS runtime_events (
    event_id TEXT NOT NULL,
    host_id TEXT NOT NULL,
    collector_id TEXT NOT NULL,
    execution_id TEXT REFERENCES executions(execution_id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    pid INTEGER, ppid INTEGER, executable TEXT,
    resource_host TEXT, resource_port INTEGER, resource_path TEXT,
    action TEXT, result TEXT, sequence INTEGER,
    intent_ref TEXT,                  -- 采集器提示，不是外键；权威关联是 P2 的 EventAttribution
    evidence_refs TEXT NOT NULL DEFAULT '[]',
    device_id TEXT NOT NULL REFERENCES device_identities(device_id),
    received_at TEXT NOT NULL,
    PRIMARY KEY (host_id, collector_id, event_id)
);
CREATE INDEX runtime_events_time ON runtime_events(host_id, occurred_at);
CREATE INDEX runtime_events_execution ON runtime_events(execution_id, occurred_at);
CREATE INDEX runtime_events_intent ON runtime_events(intent_ref);
```

`_migrate_v5()` 只做 `ALTER TABLE ADD COLUMN`，用 `PRAGMA table_info` 保护幂等（SQLite 的 ADD COLUMN 不可重复执行）；在 `migrate()` 中于 `executescript(DDL)` **之前**取 `has_v5 = "executions" in tables`，与现有 `has_v1/has_v2/has_v4`（`schema.py:279-282`）同时机，随后 `if has_v4 and not has_v5: _migrate_v5(conn)`。fresh DB 走 DDL 新列，v4 旧库走 ALTER。

**复用的既有模式**

- repo 的 `insert/get/list` + 参数化 SQL + `with self._storage._lock, self._storage.connection()` + `BEGIN` 事务：`backend/storage/repositories.py:74-200`、`576-640`
- 幂等 `ON CONFLICT ... DO UPDATE`：`backend/storage/repositories.py:568-576`
- `now_iso()` 时间文本：`backend/storage/repositories.py:45-46`
- 终态校验器风格：`backend/domain/detector.py` 的 `_check_terminal_state`
- `StrictModel`（extra=forbid）：`backend/domain/asset.py:22-23`

**测试要点**

- 契约：`PreToolUse` 之外的 `hook_event_type` 携带 `decision != not_applicable` → `ValidationError`（锁死「策略判断只在执行前」）；`params_sha256` 必须 64 位十六进制；`RuntimeEvent` 用 `model_fields` 断言无 prompt/secret 字段（防将来手滑）
- 迁移：构造真实 v4 库 → `Storage(db)` → 断言三表存在、`device_identities.host_id` 已加且为 NULL、`schema_version == "5"`；`migrate()` 连跑三次行数不变
- repo：同 `execution_id` 重放返回 duplicate 不产生第二行；`running → completed` 可推进、反向被拒；`UNIQUE(host_id, product, session_id)` 冲突；`runtime_events` 按复合主键重放幂等；保留策略删 execution 级联删 intents/runtime_events 且不影响 `detector_runs`

**验收**：A4 的契约侧（无 prompt/secret 字段）。**回滚**：纯增量迁移，revert 即净身；彻底清理的 `DROP TABLE` 脚本放 `docs/runbooks/`，本仓不做反向迁移。

---

## S2 — AgentProductAdapter 框架、两个适配器与能力矩阵

**目标**：按 `DetectorAdapter` 同款风格建立产品适配器抽象；实现 Claude Code 与 Codex 协议映射；能力矩阵以代码常量呈现；Codex 全条目显式 `unverified` 且被校验器禁止声明 `deny`。

**新增文件**

- `backend/domain/product.py` — `AgentProductDescriptor`、`HookEventCapability` 契约；校验器：`UNVERIFIED` 不得含 `deny` 且 `decision_protocol` 必须为 `"none"`；`VERIFIED` 必须带 `verified_against` 与 `evidence_ref`；`confirm/deny` 只在 `pre_execution=True` 时合法
- `backend/adapters/products/base.py` — `AgentProductAdapter` ABC（`descriptor()` / `collector_id()` / `parse_hook_input()` / `render_directive()` / `unsupported_fields()`）+ 中性 `HookEvent`、`HookDirective`、`HookResponse` dataclass
- `backend/adapters/products/claude_code.py` — Claude Code hook stdin JSON ↔ `HookEvent`；`HookDirective` → `(exit_code, stdout)`；`collector_id = "claude-code-hook-v1"`
- `backend/adapters/products/codex.py` — Codex 映射；每条目 `verification = UNVERIFIED`，`decision_protocol = "none"`，`confirm/deny` 进 `unsupported`
- `backend/adapters/products/capabilities.py` — `PRODUCT_CAPABILITIES` 代码常量矩阵
- `backend/adapters/products/__init__.py` — 照 `backend/adapters/detectors/__init__.py`
- `backend/products/registry.py` — `ProductCatalog`（`ids()/get()/descriptors()`，懒加载 + 缓存，逐行对照 `backend/detectors/registry.py:29-72`）
- `docs/adr/0006-agent-product-hook-protocol.md` — 为什么 hook 而非 MCP；为什么 exit 2 永不使用；为什么未验证产品 observe-only
- `docs/hook-protocols/claude-code.md`、`docs/hook-protocols/codex.md` — 四类事件输入字段、退出码、stdout 决策格式，逐条注明来源；Codex 文档列明未知项与「未验证」含义
- `tests/test_product_adapters.py`
- `contracts/agent-product-descriptor.schema.json`（生成）

**修改文件**

- `backend/domain/enums.py` — 新增 `CapabilityVerification`（VERIFIED / UNVERIFIED）
- `backend/domain/__init__.py`、`scripts/export-schemas.py`
- `backend/server.py` — 新增 `GET /api/v1/products`（控制台 `Permission.READ`），数据来自 `ProductCatalog.descriptors()`
- `backend/api/__init__.py` — 文档字符串改为反映「手写 `BaseHTTPRequestHandler` + 本包承载 `/api/v1` 路由」的现实（现文案宣称 FastAPI，与 `server.py` 不符）

**协议映射要点（Claude Code）**

`HookEvent` 采集字段：`event`、`session_id`、`cwd`、`permission_mode`、`tool_name`、`tool_input`（脱敏前，仅内存）、`tool_result`（脱敏前，仅内存）、`occurred_at`、`transcript_path`（仅本地定位，禁止外传）。`render_directive` 三种决策统一走 stdout，**永不使用 exit 2**（exit 2 语义是「阻断并把 stderr 回喂给模型」，observe 模式下误触即未声明的拦截；结构化 stdout 才是机器可判定的通道）：

| directive | exit_code | stdout |
|---|---|---|
| observe | 0 | 空 |
| allow / ask / deny | 0 | `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"<值>"}}` |

非 `PreToolUse` 事件调 `render_directive` 一律返回 observe（适配器内部硬编码，不依赖调用方自觉）。

**测试要点（覆盖 A1）**：三类 fixture 驱动——① 对 `PreToolUse` fixture 分别注入三种 `HookDirective` 断言 exit code 与 stdout JSON 精确相等；对 `SessionStart/PostToolUse/SessionEnd` 注入 `deny` 断言被压成 observe；② 字段兼容：断言解析出的 `HookEvent` 字段集合，缺字段/多字段/类型错误必须明确失败；③ 能力矩阵：Codex 每条目 `verification == UNVERIFIED` 且 `deny not in capabilities` 且 `decision_protocol == "none"`；Claude Code `PreToolUse` 条目 `VERIFIED` 且带 `evidence_ref`；直接构造「UNVERIFIED + deny」descriptor 断言 `ValidationError`。

**验收**：A1 全部；A3 的能力声明侧。**回滚**：纯代码+文档+生成 schema，revert 即净身。

---

## S3 — 真实 Claude Code 协议尖峰

**目标**：用一次真实 Claude Code 会话，把 S2 基于官方文档的协议假设变成事实；产出真实 fixture 并修正适配器。**这是 S4/S5 的奠基片**——摄入链与端侧包都建立在「适配器解析字段 = 真实 payload」之上。

**交付物**

- `scripts/record-claude-hooks.py` — 约 20 行 stdlib 录制脚本：stdin JSON 原样 append 到 `~/.asgp/spike/recorded-<event>.jsonl`，恒 exit 0，不触网、不写库
- `tests/fixtures/hooks/claude-code/*.json` — 由真实录制**提升**而来的 fixture（SessionStart/PreToolUse/PostToolUse/SessionEnd 各至少一条，含一次 Bash 与一次 Edit 的 `tool_input` 真实形状）
- 尖峰报告（对话内交付，或 `docs/hook-protocols/claude-code.md` 的「实测记录」小节）：逐字段比对「官方文档声明 vs 真实 payload」，列出偏差与处置

**流程**（每一步都可中断回退）

1. 备份 `~/.claude/settings.json` → 安装录制 hook（四条事件各一条 command，指向 `scripts/record-claude-hooks.py`）→ **执行门禁：此步改动用户真实 Claude Code 配置，须用户明确确认后才执行**
2. 真实会话中触发：Read 一次、Bash 一次、Edit 一次、结束会话
3. 卸载录制 hook → 校验 settings.json 与备份逐字节相同（`--uninstall` 语义同 S5 安装器）
4. 用录制 payload 跑 S2 适配器：比对每个事件的解析结果；**偏差 → 改 `backend/adapters/products/claude_code.py` 与 fixture 测试**，文档同步更新
5. 把真实 payload 提升为 `tests/fixtures/hooks/claude-code/` 的正式 fixture，S2 的三类协议测试改用它驱动

**验收**：A1 的「字段兼容」从文档假设升级为实测证据；`tests/test_product_adapters.py` 全绿且驱动数据来自真实会话。**回滚**：卸载录制 hook + 还原 settings.json；fixtures 与适配器修正保留（它们让 S2 更正确，不是回滚对象）。

---

## S4 — 设备认证的 `/api/v1` 上报端点、host 绑定与 token 轮换

**目标**：开放三个设备写入端点与两个控制台读端点，建立「服务端覆盖 host 身份」的权威链路，补齐 token 吊销/轮换，用 `ActorKind.DEVICE` 记审计。

**新增文件**

- `backend/api/v1.py` — `/api/v1/*` 路由实现；`Handler` 只做委托，避免 `server.py`（现 593 行）继续膨胀
- `backend/services/event_ingestion.py` — Execution/Intent/RuntimeEvent 写入、幂等判定、host 覆盖、`reject_secret_shaped()` 粗粒度 secret 形状闸门、批量事件的全有或全无校验与逐项错误清单
- `tests/test_v1_ingest.py` — HTTP 级测试（真实 `ThreadingHTTPServer` + httpx，照 `tests/test_console_auth.py:30-68` 的 `api` fixture）

**修改文件**

- `backend/server.py`：
  - `_dispatch()`（现 255-327 行）增加设备认证分支：命中 `DEVICE_AUTH_ROUTES` 时走 `auth_service.resolve_device(self._token())`（该函数已存在于 `auth_service.py:101-112`，当前无 HTTP 入口），设 `actor_kind=ActorKind.DEVICE`、`actor_id=device.device_id`、`self._device = device`；**控制台会话令牌访问设备端点返回 401**（防控制台用户伪造设备数据）；该分支必须先于 `_required_permission()` 的权限表判定
  - `_required_permission()`：`/api/v1/products`、`/api/v1/executions`、`/api/v1/executions/{id}/timeline`（GET）返回 `Permission.READ`（控制台读）；设备写路径不经过权限表
  - 新增 `POST /api/devices/{id}/rotate`、`PATCH /api/devices/{id}` 支持 `host_id`
  - 新增 `ASGP_V1_ENABLED`（默认 1）开关：置 0 时设备端点一律 503，控制面不停库即可切断摄入（全局 kill switch）
  - 摄入端点用独立 `ASGP_INGEST_MAX_BODY_BYTES`（默认 16 MiB），不复用 8 MiB 的 `MAX_BODY_BYTES`（`server.py:47`）
- `backend/services/auth_service.py` — `bind_device_host()`、`rotate_device_credential()`
- `backend/storage/repositories.py` — `DeviceIdentityRepository` 增加 `set_host()`、`rotate_credential()`（新 token 只返回一次、`credential_rotated_at` 落库、`credential_hash` 替换、旧 token 立即失效的硬切换）；`resolve()` 的 SELECT 覆盖新列
- `API_CONTRACT.md` — §4 从「草案」补成「已实现」：请求/响应字段、`duplicate` 语义、错误码表（`unknown_execution` / `execution_id_conflict` / `host_unbound` / `suspected_secret_parameter` / `device_token_required` / `v1_disabled`）
- `tests/test_console_auth.py` — 追加轮换/吊销/绑主机用例

**端点契约（对 `API_CONTRACT.md` 草案的两处显式澄清，需在文档标注 delta）**

1. `execution_id`/`intent_id`/`event_id` **由端点生成并在重试中保持稳定**（`DATA_MODEL.md:110` 对 event_id 的规定推广到 execution/intent）。理由：outbox 必须能离线按序落库；若由服务端发号，端点断网时无法把 intent 关联到尚未创建的 execution。服务端用 `UNIQUE` + host 归属校验防抢注：同一 `execution_id` 但 `host_id` 不属于本设备 → 409 `execution_id_conflict`。
2. `POST /api/v1/executions` 是**创建 + 收尾两用**（SessionStart 建、SessionEnd 补 `ended_at`/`outcome`）。状态只进不退：库中已是终态时，`running` 的重复上报不得把 outcome 改回去；重放一律 200 + `duplicate: true`。

**host 覆盖链路**：S1 迁移已加 `device_identities.host_id` 列 → 管理员 `PATCH /api/devices/{id}` 绑定 → 摄入时请求体里的 `host_id` 被完全忽略，服务端用设备行的值覆写；未绑定返回 409 `host_unbound` 并在 detail 中说明需先绑定。端点侧遇 `host_unbound` 记录进 `dead` 并带可读原因，不无限重试。

**测试要点**：设备令牌可写、匿名 401（带 `WWW-Authenticate`）、控制台令牌 401、吊销后 403、轮换后旧 401 新 200；重放 `execution_id` → 第二次 200 + `duplicate: true` 且库中仍一行；SessionEnd 把 `running` 推进为 `completed` 后再重放 SessionStart 报文 outcome 不变；跨设备 `execution_id` 冲突 409 且原行未改写；`runtime-events:batch` 同 `(host_id, collector_id, event_id)` 重放 `duplicates` 递增、行数不变，批量中一条非法 → 400 且整批零写入、错误清单含 `index`/`event_id`/`code` 但不含任何提交值；`host_id` 伪造（请求体写 `host_attacker`）落库值是设备绑定的 `host_bound`；secret 形状闸门：`sk-ant-...`/`AKIA...`/`-----BEGIN...`/`authorization` 键非空值 → 400 `suspected_secret_parameter`，且 400 body 与审计 detail 中都不出现该值（`assert secret not in response.text`），同时「看似敏感其实合法」用例（40 位十六进制 commit SHA、名为 `token_file` 的路径）必须通过；审计：`GET /api/audit?actor_kind=device` 能读到摄入记录、`actor_id == device_id`、detail 只有计数与 `duplicate`；`ASGP_V1_ENABLED=0` → 503 且其它端点不受影响；保留策略端到端（executions 保留 1 天，插入 2 天前数据，prune 后 execution/intent/runtime_event 一并消失、detector_runs 不受影响）。

**验收**：A2 的控制面侧（幂等）；A4 的服务端侧（secret 闸门 + 日志不含秘密）。**回滚**：revert 停端点；或 `ASGP_V1_ENABLED=0` 只断流不停码。已入库数据原位不动，重新上线后 timeline 仍可查。

---

## S5 — `endpoint/` 端侧包

**目标**：按用户决策在 `endpoint/`（与 `backend/` 平级）建立端侧目录，纯标准库实现，可在 Agent 主机用系统 `python3`（3.11+）直接运行。

**新增文件**

- `endpoint/__init__.py` — 只依赖标准库，不 import `backend/`（理由见决策 §5.4）
- `endpoint/config.py` — `EndpointConfig`：`~/.asgp/endpoint/config.toml`（`tomllib`）+ 环境变量覆盖；`server_base_url`、`device_token`、`state_dir`、`product`、`fail_mode`（`observe` 默认 / `deny`）、`collector_id`、`batch_size`、`max_attempts`；`state_dir` 永不落在仓库内
- `endpoint/redaction.py` — 端侧脱敏：从环境收集 secret 形状值、对任意 JSON 递归替换为 `[密钥已脱敏]`、生成参数摘要与 `sha256`
- `endpoint/protocols/`（`__init__.py`、`claude_code.py`、`codex.py`）— stdlib 版协议映射，产出与 backend 适配器同形的中性事件 dict
- `endpoint/outbox.py` — SQLite 持久 outbox（WAL + `synchronous=FULL`）
- `endpoint/reporter.py` — 批量上报器（`urllib.request`，不引第三方）
- `endpoint/hook.py` — `python3 -m endpoint.hook`：stdin → 协议解析 → 脱敏 → 落 outbox →（仅 PreToolUse 且 `fail_mode=deny` 时）输出决策 → 退出；**observe 模式下恒 exit 0、stdout 空**
- `endpoint/flush.py` — `python3 -m endpoint.flush [--once|--watch] [--interval N]`
- `endpoint/install.py` — 合并 `~/.claude/settings.json` hook 条目（先备份、幂等、只删自己加的条目）、写 `config.toml`（0600）、`--print` 只打印不写、`--uninstall` 还原
- `endpoint/README.md` — 安装、配置、目录结构、权限模型、已知限制
- `tests/test_endpoint_redaction.py`、`test_endpoint_outbox.py`、`test_endpoint_hook.py`

**修改文件**：`conftest.py`（把 `endpoint/` 加入 `sys.path`，与现有插入 `backend/` 同式）、`.gitignore`（追加 `endpoint/state/`）。

**outbox 表与 at-least-once 语义**

```sql
CREATE TABLE outbox (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    record_id TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,               -- execution | intent | runtime_event
    endpoint TEXT NOT NULL,
    payload TEXT NOT NULL,            -- 已脱敏 JSON
    state TEXT NOT NULL DEFAULT 'pending',   -- pending|inflight|sent|dead
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT NOT NULL,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX outbox_due ON outbox(state, next_attempt_at);
```

hook 进程只做一件事：同一事务内 insert 后 commit 然后退出（毫秒级，不触网）。`flush` 按 `seq` 升序取 `state='pending' AND next_attempt_at<=now` 标 `inflight`，**顺序发送且遇首个失败即停**（保证 execution 先于其 intent 到达，满足外键），成功标 `sent`，失败 `attempts+1` 并按 `min(2**attempts, 300)` 秒退避回 `pending`；4xx（除 408/429）直接进 `dead` 并写 `last_error`，避免毒记录永久堵队列。崩溃发生在「服务端已 200 但本地未标 sent」之间时重发，服务端唯一约束使其成为 no-op——这正是 S4 要求客户端 ID 稳定的原因，两端语义必须对齐。`sent` 记录按 `updated_at` 保留 N 天后 `DELETE` 压实。

**测试要点**：环境里的 `*_API_KEY`/`*_TOKEN` 值在嵌套 dict/list/字符串中被替换；摘要截断与 `sha256` 稳定；**drift 守卫**——import `endpoint.redaction` 与 `backend.adapters.detectors.subprocess.redact`，对同一 secret 样本断言替换结果一致；outbox enqueue→claim→ack 全流程、进程退出后重开库记录仍在、同 `record_id` 重放不产生第二行、失败退避与 `dead` 迁移、崩溃模拟（ack 前杀进程）后重发得到服务端幂等；喂 Claude Code 四类事件 fixture → 断言 outbox 行数与 payload 字段；`fail_mode=observe` 时即使本地规则命中也是 exit 0 + 空 stdout；`fail_mode=deny` 时 PreToolUse 输出正确 `permissionDecision`；**断言 payload 中绝不出现 `transcript_path`、`permission_mode`、原始 `tool_input` 键名、prompt 文本**；**协议 drift 守卫**——import `endpoint.protocols.claude_code` 与 `backend.adapters.products.claude_code`，对同一 fixture 断言两者产出的中性事件 dict 相等。

**验收**：A2 的端侧；A3（offline 排队 + observe 降级 + 未验证标注）；A4（脱敏 + 无 prompt/环境变量外传）。**回滚**：`--uninstall` 移除 hook 条目并还原备份；`~/.asgp/endpoint` 数据保留，重装后可续传（服务端幂等）。控制面完全无感。

---

## S6 — timeline 查询 API 与最小 web UI（限界版）

**目标**：提供 `GET /api/v1/executions/{execution_id}/timeline`，让 A2 可被人眼验证；UI 必须显式标注归因/发现项/策略决策尚未实现。

**新增文件**

- `backend/services/timeline_service.py` — 合并 intents + runtime_events 按 `occurred_at` 排序，tie-break 为 `(kind, id)`；游标分页
- `backend/domain/timeline.py` — `TimelineEntry`、`TimelineResponse` 契约；含 `sections_supported` / `sections_pending` 与 `attribution_supported: bool = False`
- `tests/test_timeline_api.py`、`contracts/timeline-entry.schema.json`（生成）

**修改文件**：`backend/api/v1.py`（增加 `GET /api/v1/executions` 列表与 timeline，均需控制台 `Permission.READ`）、`scripts/export-schemas.py`、`web/index.html`、`web/app.js`、`web/styles.css`（新增「运行时时间线」导航项与面板；现有 `web/` 是无构建静态 SPA，增量约 150 行 JS + 40 行 HTML/CSS，零新依赖）。

**响应形状（关键在「不宣称已完成」）**

```json
{
  "execution_id": "exec_...",
  "product": "claude-code",
  "capability_verification": "verified",
  "host_id": "host_...",
  "sections_supported": ["intent", "runtime_event"],
  "sections_pending": ["attribution", "finding", "policy_decision"],
  "attribution_supported": false,
  "attribution_note": "EventAttribution 归因服务属于 P2；intent_ref 仅为采集器提示，不是归因结论。",
  "entries": [{"kind": "intent", "occurred_at": "...", "attributions": [], "intent": {"...": "..."}}],
  "next_cursor": null
}
```

**UI 限界**：只读；一个 execution 选择器 + 一条纵向时间线 + 未验证徽章；不做筛选、不做归因可视化、不碰扫描页。`unverified` 渲染琥珀色徽章与脚注「该产品 Hook 协议未在本环境实测，能力条目为声明值，不得据此宣称已拦截」；**永远不渲染绿色的「已支持」**。

**测试要点**：同秒事件排序稳定性；游标翻页不重不漏；`capability_verification` 透传；不存在的 execution_id → 404；未认证 401；`sections_pending` 恒含 `attribution`（测试锁定这个诚实标记）。

**验收**：A2 的人眼验证通道；A3 的报告标注侧。**回滚**：只读 API + 静态资源，revert 即净身。

---

## S7 — E2E 脚本、runbook 与文档收口

**新增文件**

- `scripts/e2e-hook-timeline.sh` — 起临时库控制面 → 管理员登录 → 登记设备 → 绑 host → 用 S3 的真实 fixture **真实调用** `python3 -m endpoint.hook`（四事件序列）→ 断言 outbox 4 条 `pending` → `--flush --once` → 断言 4 条全 `sent`、timeline 条目数与顺序、`capability_verification=verified`、`params_summary` 无秘密 → 幂等（再 flush 零新增）→ 负面对照（停机时入队恢复后无重复；吊销后 403 进 `dead`；假 `DEMO_API_KEY` 不出现在上传体）→ `--uninstall` 后 settings.json 与备份逐字节相同
- `docs/runbooks/p1-hook-onboarding.md` — 登记设备、绑 host、装 hook、轮换令牌、卸载；每步预期输出与失败处置

**修改文件**：`README.md`（P1 已实现/未实现项）、`IMPLEMENTATION_PLAN.md`（P1 四条验收逐条标注达成与证据链接）、`API_CONTRACT.md` 与 `DATA_MODEL.md`（标注本阶段 delta：客户端生成 ID、Execution upsert、asset_instance 无外键）。若联调发现协议偏差，改适配器并**必须同步补 fixture 测试**。

**验收**：A1-A4 全量 + 联调证据（timeline JSON/截图、outbox 状态快照、负面对照输出）。**回滚**：无产品代码改动，`--uninstall` 即回到 S6 状态。

---

## 关键设计决策

1. **表结构**：`execution_id`/`intent_id` 端点生成；`runtime_events` 复合主键 `(host_id, collector_id, event_id)` 落实 `DATA_MODEL.md:110` 的服务端幂等规则。唯一约束 `executions(host_id, product, session_id)`（一次会话一条 execution，防端点重装重复上报）与 `intents(execution_id, tool_call_id)`（Pre/Post 两事件不裂成两行；`tool_call_id` 为 NULL 时 SQLite 唯一约束不触发，语义正确）。外键级联：intents/runtime_events → executions CASCADE；`parent_intent_id` 自引用 P1 恒 NULL 为 P2 预留；`intent_ref` 故意不是外键（采集器提示，权威关联是 P2 的 EventAttribution，与 ADR 0003 一致）。`asset_instance_id` 无外键——P1 范围不含资产注册表，只存客户端引用，注释与文档写清。
2. **设备认证复用 P0 机制，不新建**：`auth_service.resolve_device()`（`auth_service.py:101-112`）+ `DeviceIdentityRepository.resolve()` + SHA-256 摘要 + `DeviceStatus` 门禁 + `touch()`。P0 已做实「设备令牌只证明上报资格、不等于控制台权限」的边界；新建一套会造成两套凭证语义并存。P1 只做三处增量：`host_id` 列 + 绑定端点、`rotate_credential()`、`_dispatch()` 设备分支。轮换采用单凭证硬切换（旧 token 立即失效），不为宽限期建多凭证表——文档规定「先取新 token 再下发」的操作顺序。
3. **outbox 用 SQLite 单文件，不用 JSONL**：需要 per-record 状态机、重试计数、`next_attempt_at`、按 `seq` 领取、跨进程协调（hook 与 flush 是两个 OS 进程）——SQLite 一行 `UPDATE ... WHERE state='pending'` 就能拿到；JSONL 要手写 fsync 协议和文件锁。WAL + `synchronous=FULL` 崩溃安全，`sent` 行定期压实，存储有界。
4. **端侧脱敏写独立 stdlib 实现，不 import backend**：① `endpoint/` 必须能在 agent 主机用系统 `python3` 运行，不依赖控制面 venv 与 Pydantic；② `import adapters.detectors.subprocess` 会先执行 `backend/adapters/detectors/__init__.py` 导入七个检测器适配器，而 hook 进程每次工具调用都启动一次，代价不可接受；③ 语义不同（backend 版面向子进程错误文本的扁平替换，端侧需要递归 JSON 遍历 + secret 形状键名识别 + 摘要/sha256）。代码漂移用 drift 守卫测试兜住（两侧实现同样本断言一致）。
5. **hook 安装用 settings.json + 一次性 stdlib 进程，不引入 MCP、不起守护进程**：MCP server 无法观测任意工具调用，拿不到 `PreToolUse` 执行前决策点，从机制上不可能满足「hook 确实位于执行前才允许阻断」；长驻守护进程 + unix socket 多一个需要 supervisor 和崩溃恢复的部件，而 hook 的实际工作量只是一次 SQLite insert。上报由用户自选的 `systemd --user` 或 cron 驱动 `flush --watch`，安装器只打印建议行、不自动改 crontab。若后续实测进程启动开销不可接受，P2 可平滑换 socket 守护进程（outbox 表不变）。
6. **capability 矩阵存代码常量，不建表**：capability 是「某产品版本的 hook 协议支持什么」的静态声明，随适配器代码发布而变化，与 `DetectorDescriptor` 由 `descriptor()` 返回（`backend/adapters/detectors/base.py:80-82`）同模式。建表连带种子数据、每次产品版本一次迁移、管理界面，P1 都不需要。矩阵可观测：`AgentProductDescriptor` 是导出契约，`GET /api/v1/products` 原样回传，前端直接渲染。
7. **Codex「未验证」三层落地**：枚举层（`CapabilityVerification`）→ 契约层（校验器强制：UNVERIFIED 不得含 deny 且 `decision_protocol` 必须为 `"none"`，VERIFIED 必须带 `verified_against` 与 `evidence_ref`）→ 呈现层（API 透传 + UI 琥珀色徽章 + 永不渲染绿色「已支持」）。未验证不是注释而是不可绕过的约束。

---

## 风险与回滚

| 切片 | 主要风险 | 处置 |
|---|---|---|
| S1 | 迁移失败导致服务起不来 | 只做 `CREATE IF NOT EXISTS` + `PRAGMA` 保护的 `ALTER ADD COLUMN`，无表重建无数据改写；revert 后旧库仍可被 v4 代码打开；`DROP TABLE` 脚本进 runbook |
| S1 | 新表无保留策略无限增长 | 保留策略与表同片闭环（`RetentionKind` + `prune()` + 测试），无「已宣告未实现」窗口 |
| S2 | 契约改动忘记重新导出 schema | 硬门禁 `test_contract_sync.py` 双向失败；提交前必跑 `scripts/export-schemas.py` |
| S2/S3 | Codex 协议是猜测 / Claude Code 文档与真实不符 | Codex 全条目 UNVERIFIED + 决策层禁止 deny + 协议文档列明未知项；S3 尖峰把 Claude Code 假设变事实并提升为 fixture |
| S4 | 设备端点被控制台令牌或匿名访问 | 设备路径独占设备认证，控制台令牌 401；匿名 401 带 `WWW-Authenticate`；未识别 `/api` 路由沿用既有探测防护 |
| S4 | 毒记录堵死摄入队列 | 批量端点整批 400 + 逐项错误清单；端点侧 4xx 进 `dead` 不无限重试 |
| S4 | 服务端覆盖 host 后端点拿不到正确 host | 未绑定 409 `host_unbound` + runbook 绑定步骤；端点记录进 `dead` 而非静默丢数据 |
| S4 | token 轮换切断在线端点 | 硬切换是已知取舍，runbook 规定「先取新 token 再下发」 |
| S5 | hook 进程拖慢每次工具调用 | observe 模式只做一次 SQLite insert 不触网；README 记录实测启动开销，超标则 P2 换 socket 守护进程 |
| S5 | settings.json 被改坏 | 写前备份、只动自己加的键、`--uninstall` 精确还原、`--print` 供人工合并 |
| S5 | 端侧与控制面协议映射漂移 | `test_endpoint_hook.py` / `test_endpoint_redaction.py` 的 drift 守卫 |
| S6 | UI 暗示归因/策略已实现 | `sections_pending` 与 `attribution_supported=false` 由测试锁定；UI 禁绿色「已支持」 |
| S7 | 联调无法闭环 | 保持 S1-S6 上线，在 `IMPLEMENTATION_PLAN.md` 记录已知限制，不标记 P1 完成 |

**全局 kill switch**：`ASGP_V1_ENABLED=0` 一键关闭 S4/S6 的所有 `/api/v1` 端点（503），不改库、不 revert 代码。

---

## 端到端验证

`scripts/e2e-hook-timeline.sh`（S7 交付，可重复）覆盖：临时库控制面启动 → 登记设备 + 绑 host → S3 真实 fixture 驱动 `endpoint.hook` 四事件 → outbox 全 `sent` → timeline 条目数/顺序/`capability_verification`/无秘密 → 幂等重放零新增 → 离线排队恢复无重复 → 吊销后 403 进 `dead` → 假密钥只以 `[密钥已脱敏]` 出现 → 卸载后 settings.json 与备份逐字节相同。

**门禁**：全部完成后 `.venv/bin/python -m pytest` 全绿（P0 基线 146 passed / 7 skipped，P1 只增不减）+ `tests/test_contract_sync.py` 通过 + `IMPLEMENTATION_PLAN.md` 的 P1 四条验收逐条有证据链接。

---

## 提交序列（中文 conventional commits，与控制面现有风格一致）

1. `feat(domain): Execution/Intent/RuntimeEvent 契约与 v5 存储迁移`（S1）
2. `feat(storage): Execution/Intent/RuntimeEvent 仓储与运行数据保留策略`（S1）
3. `feat(products): AgentProductAdapter 与 Claude Code/Codex 能力矩阵`（S2）
4. `docs(adr): 0006 产品 Hook 协议边界与未验证能力约束`（S2）
5. `test(products): 真实 Claude Code hook 协议尖峰与 fixture`（S3）
6. `feat(api): 设备认证的 /api/v1 上报端点与主机身份覆盖`（S4）
7. `feat(auth): 设备令牌轮换与主机绑定`（S4）
8. `feat(endpoint): 端侧 hook 接收、本地脱敏与持久 outbox`（S5）
9. `feat(endpoint): Claude Code settings.json 安装器`（S5）
10. `feat(api): Execution timeline 查询与运行时时间线页面`（S6）
11. `test(e2e): hook 到 timeline 全链路脚本与联调证据`（S7）
12. `docs(p1): 更新实施计划、API 契约与数据模型的已实现边界`（S7）

---

## 执行门禁（需用户明确确认的动作）

- **S3 与 S5 会修改用户真实的 `~/.claude/settings.json`**（安装 hook 条目）。执行到这两步前须向用户确认；安装器/录制器必须：先备份、只动自己加的键、`--uninstall` 精确还原、提供 `--print` 人工合并选项。S3 尖峰结束即卸载录制 hook，S5 的正式 hook 是否常驻也由用户决定。
- 每片合入前跑该片验证命令与 `test_contract_sync.py`；提交遵循控制面中文 conventional commit 风格；不提交构建产物；`~/.asgp/` 端侧状态目录永不进仓库（`.gitignore` 已防御 `endpoint/state/`）。
