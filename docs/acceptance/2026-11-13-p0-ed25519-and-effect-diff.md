# P0 服务端 Ed25519 验签 × 指令来源谱系与 OS 副作用差分（2026-11-13）

本轮围绕「单点突破 + 补齐唯一伪证据缺口 + 控制台聚焦」交付三项能力：

1. **P0 修复（Schema v11）**：`asset_releases.signature_verified` 改为服务端真实 Ed25519（RFC 8032）验签，消除客户端自报布尔字段。
2. **核心突破（Schema v12）**：引入 `Intent.source_kind` / `Intent.source_ref` 指令来源谱系，并实现 `EffectDiffService`（`effect-diff-v1`）把「工具调用预期作用域」与「归因到的 Linux Audit 真实 OS 事件」做集合差分。
3. **控制台聚焦优化**：按「核心证据链」与「治理与配置」重组侧栏，上线 Publisher 公钥台账与验签入口、`EffectDiff` 差分对比视图与处置联动，以及概览实时离线评测对照卡。

---

## 1. P0：服务端 Ed25519 验签（Schema v11）

- **纯标准库密码原语**：新增 `backend/services/ed25519.py`，实现 RFC 8032 Ed25519 公钥解码与曲线点校验（无新增外部加密库依赖），并与 OpenSSL 3.0.13 实测交叉验证。
- **表结构与迁移**：`backend/storage/schema.py` 升级至 `SCHEMA_VERSION = 11`，新增 `publishers` 表及 `asset_releases` 的 `publisher_id` / `signature` / `verified_at` 字段；迁移时**强制清空历史未验证的客户端自报 `signature_verified = 1` 记录**。
- **服务端强制拒伪造**：`AssetService.register_release` 若收到客户端直接提交的 `signature_verified`，统一返回 `400 client_signature_verified_forbidden`；仅当 `publisher_id` 对应激活态公钥对 `content_hash` 验签通过时，服务端才置位 `signature_verified = True`。
- **边界**：控制台与 API 支持发布者公钥注册与吊销（`GET/POST /api/v1/publishers`、`POST /api/v1/publishers/{id}/revoke`），尚未接入外部企业 PKI / 证书透明日志。

---

## 2. 核心单点突破：指令来源谱系 × OS 副作用差分（Schema v12）

> 传统规则只看单条工具名或静态参数关键字，无法区分「用户直接允许的合理操作」与「低信任 Skill / MCP 伪装高可信工具名诱导出的越界 OS 行为」。

- **来源谱系贯穿端到端**：
  - 领域枚举：`SourceKind`（`user_task / workspace_config / installed_skill / mcp_server / tool_output / unknown`）与 `EffectDiffVerdict`（`within_expected / undeclared_side_effect / unverified / no_observed_effect`）。
  - 端侧：`endpoint/hook.py` 支持通过 `ASGP_SOURCE_KIND` / `ASGP_SOURCE_REF` 注入来源，并在 `PreToolUse` / `PostToolUse` 合并入库时用 `COALESCE` 保留首次来源声明，防止后置事件冲掉 `source_kind`。
- **共享判定真值**：抽离 `backend/services/evidence_rules.py`，统一管理 `SENSITIVE_MARKERS`、`TRUSTED_HOSTS`、`TRUSTED_SUFFIXES`、`normalize_hint_path`、`is_sensitive_path`、`is_external_host`，与 `DataFlowService` 共用，避免规则分叉。
- **Linux Audit 真实事件对齐**：`EffectDiffService`（`GET /api/v1/executions/{id}/effect-diff`）覆盖 `read / write / network / exec` 四类工具与 `file_access / network_connect / process_start / process_exec` 系统事件。对未归因到任何 Intent 的后台事件继续严格**留空计入 `unattributed_event_count`**，绝不按时间最近邻硬连。

### 2.1 实测结果（全部为最新实测口径）

| 测试 / 评测项 | 结果 | 关键数字 | 边界说明 |
| --- | --- | --- | --- |
| **反事实 A/B 评测**（`scripts/lab/eval_effect_diff.py`） | 通过 | **16 组**（8 恶意 A 组 + 8 反事实 B 组）：ASGP 捕获率 **1.00（8/8）**、误报率 **0.00（0/8）**；仅看工具名/参数基线捕获率 **0.00（0/8）** | 离线可控 `TemporaryDirectory` 端到端管线回放（`Ingestion -> Attribution -> EffectDiff`） |
| **在线库真实执行验证**（`exec_a327161ede645869a326ffde47d9c8c6`） | 通过 | 1 条 Intent；已归因事件 **43** 条；`within_expected=35`、`undeclared_side_effect=7`；同窗未归因 **20,061** 条诚实留空 | 该历史执行未带 `source_kind`，归为 `unknown`；修复 `process_start` 分类后消除原 4 条 `unverified` |
| **数据外发链标注集**（`scripts/lab/eval_dataflow.py`） | 通过 | 30 条序列：检出 **15/15（100%）**、误报 **0/15（0%）** | 本轮修复 `eval_dataflow.py` 30 场景同秒混叠导致的时间窗回退交叉误报，改按独立 10 分钟槽位隔离 |
| **行为归因标注集**（`scripts/lab/eval_attribution.py`） | 通过 | 10 场景 13 事件：`selected` 精度 **0.8333** / 召回 **0.625**；`any_edge` 精度 **0.8889** / 召回 **0.875** | 与既有标注集 `docs/acceptance/attribution-eval.json` 一致 |
| **全量自动化测试**（`./scripts/test.sh`） | 全绿 | **457 passed（130.20s）**；硬编码扫描 `81` 代码文件 / `30` 测试文件 **0 发现** | 新增 `TestEd25519ReleaseVerification`、`TestEffectDiff` 等；`export-schemas.py --check` 通过 |

---

## 3. 主机 b（`116.62.28.177`）端侧同步与 `qwen-code` 实测边界记录

- **已完成的端侧工作**：
  1. 向主机 `b` 同步最新 `endpoint/*.py`（包含 `endpoint/hook.py` 对 `ASGP_SOURCE_KIND`/`ASGP_SOURCE_REF` 及 `qwen-code` Node 进程 `hook_anchor` 识别修复），全部 `py_compile` 通过。
  2. 执行 `endpoint.audit --once`（采集 874 条事件）与 `endpoint.flush`，将历史积压清零（`sent=37, dead=0, pending=0`），线上控制面总运行时事件升至 **22,508** 条。
  3. 跑通首条带溯源标记的真实 `qwen-code 0.26.8` 执行 `exec_d2645ee3a01b56688a6638bca7ca5947`（`run_shell_command`，`source_kind="user_task"`，`source_ref="ab1_b_clean_pkg_check"`，`PreToolUse` + `PostToolUse` 共 3 条记录落盘本地 `outbox.db` 等待上报）。
- **遇到的真机硬件边界（诚实披露）**：
  - 测试机 b 为 `1.7 GiB` 物理内存无预设 Swap 的 ECS，运行 `qwen-code` 时 `MainThread`（Node）`anon-rss` 约 `1.11 GiB` 触发 Linux `oom-killer`；随后临时挂载 `2 GiB /swapfile` 并再次拉起 `qwen` 后，高磁盘 Swap 抖动导致 `116.62.28.177:22` SSH 在 `banner exchange` 阶段持续超时（主机 a 上 `asgp-test-tunnel` 日志同步记录 `Timeout, server 116.62.28.177 not responding`）。
  - 因此多组真机 `qwen-code` A/B 实时回传尚未全部 flush 到主机 a；需在阿里云控制台重启主机 b 并移除 `/swapfile`（或使用轻量进程替代完整 Node CLI 做 A/B 真机采录）后继续。
