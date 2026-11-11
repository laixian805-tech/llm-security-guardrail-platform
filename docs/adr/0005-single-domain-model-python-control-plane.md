# ASGP 只保留一套领域模型：Python 控制面为唯一权威

状态：已采纳。

ASGP 的领域模型只有一份，位于 `/root/agent-security-fusion-platform`（Python 模块化单体，FastAPI + SQLAlchemy + Pydantic，契约锁定在 `contracts/*.schema.json`）。`/root/asgp-v1`（A.I.G fork）只提供 Skill/MCP/Agent 三个独立扫描器，通过版本化 Detector Adapter 接入，不再承载 ASGP 的 Asset/Instance/Release、Finding/DetectorRun、Execution/Intent、Event/Incident/Evidence 任何一张表。

此前在 A.I.G fork 内曾建有一套 Go `asgp/` 包（11 张 `asgp_` 前缀表），与本控制面并行。该包已整体退出架构：包删除、`common/websocket/server.go` 的 store 初始化摘除、开发库中 11 张空表及 67 个索引移除。之所以不必惋惜，是因为它与契约的分歧是结构性的而非细节性的：资产身份用 `(asset_type, canonical_uri)` 唯一索引而契约用 `canonical_name`；Finding 去重用单字段 `dedup_key` 加 `version`/`occurrence_count`，而契约是 `UNIQUE (detector_id, fingerprint)` 加 `detector_run_findings` 联结表；时间用 int64 毫秒而契约用 ISO-8601；`DetectorRun.status` 只有 `running/completed/failed/cancelled` 四值，无法表示 `timed_out` 与 `output_limit_exceeded`，而这正是「扫描器超时不被显示为 clean」这条验收标准的数据层前提。两套模型不存在无损映射，且该包无任何 HTTP 路由、无读写、11 张表行数全为 0，维护成本是纯负担。这与 ADR 0001（不合并 A.I.G 完整平台）和 ADR 0004（控制面为模块化单体）是同一条边界的两次执行。

A.I.G fork 内**保留**的部分与领域模型无关，是扫描器执行层的安全加固，必须继续维护：API Key 不再进入进程 argv，改为经 `utils.RunCmdWithSecretEnv` 以 `LLM_API_KEY` 环境变量注入；命令日志与 WebSocket 参数经 `RedactJSON`/`redactParams` 脱敏；子进程带进程组看门狗。这些满足 P0 验收「API Key 不进入日志、数据库和进程 argv」。`scripts/verify-no-leak.py` 是该项的回归手段，随扫描器一起保留。

若未来确实需要把 A.I.G 的完整红队控制台作为产品核心，按 ADR 0001 的前提重新评估：先完成认证/RBAC、Worker 权限收敛、数据模型映射和 NOTICE 审查，再讨论平台级 fork。在那一之前，任何在 A.I.G fork 内新增 ASGP 领域表的提案都应先修正本 ADR。
