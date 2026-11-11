> 后续开发更新：本文件保留接手前快照。用户随后授权在 116.62.28.177 同时接入 Codex/Claude；开发与实测进展以 [P1 实测报告](acceptance/2026-11-11-p1.md) 为准，原文“未实现/未验证”不代表当前状态。

# ASGP 项目接手梳理

核对日期：2026-11-11（北京时间）。本说明对照了项目文档、Git、现有代码、Claude 会话和本机数据库；测试结果为本次复跑结果。它是接手时的状态快照，不是 P0/P1 的正式验收通过报告。

## 1. 项目要做什么

ASGP（Agent Security Governance Platform）是独立的 Agent 安全治理平台。最终需要串起四件事：

1. 识别 Agent、Skill、MCP Server、插件及其安装实例和内容版本。
2. 复用多个检测器，保留检测来源、规则、原始报告和标准 Finding。
3. 把 Agent 的会话、工具调用与主机进程、文件、网络事件建立有证据的关联。
4. 通过策略、准入、审批、Incident、修复和复测完成治理闭环。

当前可运行能力主要在第 2 项及控制台认证、审计、保留策略；第 3 项的 Hook 契约和存储已开始实现，第 4 项仍属于后续阶段。

几个贯穿项目的边界：Finding 是检测发现，不能直接等同于风险结论；Execution 是一次任务/会话，不能等同于 PID；Intent 是观测到的操作请求，不从 prompt 猜测；PolicyDecision 只是决定，必须另有 EnforcementEvidence 才能宣称实际阻断；时间相关性不能直接写成因果归因。

## 2. 代码库与部署边界

| 位置 | 角色 | 接手判断 |
| --- | --- | --- |
| `/root/agent-security-fusion-platform` | ASGP 权威控制面、领域契约、前端和后续端侧包 | 本轮主要开发仓库 |
| `/root/asgp-v1` | A.I.G fork，提供 Skill/MCP/Agent 独立扫描器及调用安全加固 | 不建立第二套 ASGP 领域模型；P1 不修改它 |
| `/root/opensrc/agent-security-landscape` | SkillSpector、Snyk、Cisco 等上游参考源码 | 经 Detector Adapter 调用，不整体并入控制面 |
| `/root/llm-security-guardrail-platform` | 旧平台与实验经验 | 参考资产身份、Hook、Audit 等概念；不直接迁移旧数据库/API/前端，不继承其验收结论 |
| `/opt/SZU-HIVEMIND` | 本机另一项目 | 与此次接手的 ASGP 无关 |

ADR 0001/0005 已确定：复用 A.I.G 的扫描器，不合并它的完整 Go/React 平台，也不恢复已删除的 Go `asgp/` 领域包。

开发机与测试机的分工以用户最新明确要求为准：**真实 Hook 安装和产品验证在测试机进行，不在本机开发环境安装。** Claude 会话中已明确收到这一要求。本次只读确认开发机 Claude 配置没有 Hook 条目；没有安装 Hook 或连接、修改测试机。

旧实验文档将 `116.62.28.177`、非 root 用户 `agentsec-lab` 列为测试端候选线索；这是旧平台历史信息，本次没有验证该机器的在线状态、当前安装版本或 ASGP 部署状态。

## 3. 项目书与文档入口

本次在 ASGP 仓库未找到单独命名为“项目书”的文件。现有项目定义由下列文档共同承载：

| 文档 | 内容与使用方式 |
| --- | --- |
| [README.md](../README.md) | 产品入口、启动、模型供应商、控制台认证和引擎边界 |
| [ARCHITECTURE.md](../ARCHITECTURE.md) | 平台目标、控制面/数据面、六层架构、运行时归因与治理闭环 |
| [DATA_MODEL.md](../DATA_MODEL.md) | 核心实体及关系，包含尚未落地的目标模型 |
| [GLOSSARY.md](../GLOSSARY.md) | 统一业务术语 |
| [API_CONTRACT.md](../API_CONTRACT.md) | API 约定、目标 `/api/v1` 与当前原型端点 |
| [IMPLEMENTATION_PLAN.md](../IMPLEMENTATION_PLAN.md) | P0/P1/P2/P3 的范围、验收和阶段门槛 |
| [P1 完整实施计划](plans/p1-hook-execution-context.md) | 从 Claude 计划文件保存的七切片计划，附接手时的状态与后续用户约束 |
| [ADR 目录](adr/) | 上游复用、供应商、证据归因、模块化单体、单一领域模型、Hook 协议边界 |
| [UPSTREAMS.md](../UPSTREAMS.md) | 引擎版本、来源、许可与执行边界 |

注意：这些文件的更新时间不同，不能把目标架构直接当作实现状态。发现的主要差异见第 8 节。

## 4. 当前实现架构

实际后端是 Python 标准库 `ThreadingHTTPServer` / `BaseHTTPRequestHandler`，领域契约用 Pydantic，数据访问用 SQLite 原生 SQL 仓储；前端为无构建步骤的 HTML/CSS/JavaScript。FastAPI、SQLAlchemy、React、PostgreSQL 出现在目标架构或依赖清单中，但不是当前服务的实际调用链。

扫描链路：静态工作台 → `backend/server.py` 的认证、权限和目标校验 → `ScanService` → `DetectorCatalog` / Detector Adapter → 独立虚拟环境 CLI → SARIF/JSON 归一化 → DetectorRun / RawReport / Finding → 查询与复核。

| 模块 | 关键位置 | 当前职责 |
| --- | --- | --- |
| HTTP 与控制台 | `backend/server.py`、`web/` | 登录、RBAC、扫描/导入/查询、审计、设备登记、保留策略；P1 增加产品能力查询 |
| 领域与契约 | `backend/domain/`、`contracts/` | Pydantic 模型与导出的 JSON Schema 双向同步测试 |
| 检测器 | `backend/adapters/detectors/`、`backend/detectors/registry.py` | 五个已注册适配器、输出归一化、超时、输出限制、环境变量与可选降权 |
| 供应商 | `backend/model_providers.py`、`backend/services/provider_probe.py` | StepFun 主用、讯飞候选，区分 Responses 和 Chat Completions，Probe 状态控制路由 |
| 扫描服务 | `backend/services/scan_service.py` | 幂等键、执行编排、失败状态与结果持久化 |
| 存储与身份 | `backend/storage/`、`backend/services/auth_service.py` | SQLite 迁移、扫描/身份/审计/保留仓储；P1 工作区新增执行仓储 |
| 产品适配器 | `backend/adapters/products/`、`backend/products/registry.py` | P1 新增的协议映射、能力声明与产品目录 |

五个已注册检测器为 SkillSpector、Snyk Agent Scan、Cisco MCP Scanner、A.I.G Skill Scan、A.I.G MCP Scan。A.I.G Agent Scan CLI 的存在不等于平台已开放动态 Agent 测试；ToolHive 和 LLM Guard 也不是当前已接通的运行时治理能力。

## 5. P0：实现已落地，正式验收待收口

控制面当前提交基线为 `72541af`；主要 P0 提交已包含领域契约、Detector Adapter、存储迁移、Provider Probe、控制台认证/RBAC、原始报告独立权限和 JSON Schema 同步门禁。扫描器仓库 HEAD 为 `33974ec`，包含密钥经环境变量注入和日志脱敏；接手检查时该仓库工作区干净。

| P0 验收项 | 现有实现/证据 | 尚需核对或补证据 |
| --- | --- | --- |
| 检测器成功、clean、部分结果、超时、非零退出、无效 JSON、输出超限 | 已有统一适配器契约测试，本次回归通过 | 五种真实引擎的完整验收矩阵；不能由假 CLI 契约测试推导全部实机通过 |
| SARIF/JSON → 标准 Finding；原始报告按权限复核 | 导入、归一化、来源保留、独立 `read_raw_report` 权限及 HTTP 测试 | 浏览器操作和代表性上游报告的验收记录 |
| 通过 detector 注册配置增减引擎 | `DetectorCatalog.ADAPTER_TYPES`，服务不写各引擎细节 | 验收时记录实际启用引擎、版本和配置 |
| StepFun/讯飞分别 Probe；协议、模型、错误和密钥边界 | Probe 与路由测试通过；Responses/Chat Completions 分开 | 现存库仅有 StepFun 两次历史 Probe：Responses 通过；扫描器 profile HTTP 402 失败；没有讯飞 Probe 记录。需重新实测并解释可用性，不能写成两家已通过 |
| 重试幂等；超时不能显示为 clean | 幂等键、Finding 指纹和超时 API 回归已实现 | 真实 HTTP 重试/并发及界面展示证据；无幂等键的新扫描不等于重试 |
| 未认证 401/403；设备身份不等于控制台权限 | 控制台认证、角色权限、令牌摘要、设备令牌隔离、请求审计与保留测试 | 部署端验证、HTTPS/反向代理和最低权限实际配置；设备运行事件摄入属于 P1 |

P0 的代码回归与正式阶段验收应分开记录。`IMPLEMENTATION_PLAN.md` 要求每阶段提交功能清单、测试结果、版本/配置、限制、迁移/回滚方案和运行证据；当前尚未见一份把全部条目签收完的 P0 验收报告。

本机数据库只读检查：`data/fusion.db` 仍为 schema v4；有 2 条 DetectorRun、4 条 Finding、1 条 RawReport、2 条 Provider Probe，控制台用户/会话、设备、请求审计均为 0 条。它只能说明该文件的状态，不能代表旧平台或其他部署端的数据库。检查时本机未发现 ASGP 的 8000 端口监听。

## 6. P1：已批准的计划与真实进度

P1 要打通：产品 Hook → 本地脱敏 → 持久 outbox → 设备认证上报 → Execution/Intent 存储 → 可查询时间线。完整计划见 [P1 计划](plans/p1-hook-execution-context.md)。

| 切片 | 目标 | 接手时的实际状态 |
| --- | --- | --- |
| S1 | Execution/Intent/RuntimeEvent、JSON Schema、v5 迁移、仓储、保留策略 | 代码已存在，领域/存储/迁移测试通过；未提交，现存业务库仍是 v4 |
| S2 | 产品适配器、Claude/Codex 能力矩阵、协议文档、产品查询 API | 代码与测试已存在且通过；未提交。新增 `GET /api/v1/products` |
| S3 | 真实 Claude Hook 协议验证，形成版本化 fixture | 只有录制脚本；无录制结果、真实 Hook fixture 或验证报告。停在只读查找本机 Claude 二进制协议资料 |
| S4 | 设备上报 API、host 绑定、令牌轮换、设备审计、secret 闸门 | 未实现；`backend/api/v1.py` 和摄入测试不存在 |
| S5 | `endpoint/` 脱敏、outbox、上报、安装/卸载 | 未实现；`endpoint/` 目录不存在 |
| S6 | Execution 列表、时间线 API 与最小只读 UI | 未实现；对应服务、契约和测试不存在 |
| S7 | E2E、runbook、文档更新和 P1 验收证据 | 未实现；联调脚本和 runbook 不存在 |

接手时工作区为 **9 个已跟踪文件修改 + 23 个未跟踪文件**，均属于上述 S1/S2/S3 工作；不含本次新增接手文档和计划副本。这些改动不能误当成已提交代码或丢弃。

产品支持的真实边界：

- Claude Code：有四类事件的解析与 allow/ask/deny 输出编码测试，但矩阵仍全部 `unverified`，仅声明 observe；没有真实产品回执，不能宣称已拦截。
- Codex：当前是明确不支持摄入的适配器，`ingest_supported=false`，解析会抛 `UnsupportedHookProtocol`。存在 `codex.py` 不等于完成第二个产品接入，也不代表 Codex 产品本身没有 Hook；这里只表示项目尚未验证。
- `RuntimeEvent` 有模型和表不等于已完成 Linux Audit 采集或归因；这两项仍在 P2。

Claude 会话中，用户已选择“按计划四条提交”S1/S2；Git 证明这些提交尚未执行。本次任务按“先梳理”处理，未代为提交。

中断位置可复核：2026-11-11 17:15:47，Claude 对自己的可执行文件运行 `strings` 和复杂正则以查找 Hook 输入结构；对应后台任务在 18:44:42 记为 killed。同一时段系统发生全局 OOM。后续直接围绕测试机产品协议和受限输入验证推进，不重复这条长时间二进制正则搜索。二进制字符串也不能替代真实 Hook 派发与产品执行回执。

## 7. 本次复跑结果

测试串行执行，并为测试命令设置超时和 2 GiB 进程虚拟地址空间上限；没有启动付费 LLM 扫描、安装 Hook、修改业务数据库或对外部署。

| 检查 | 方法 | 结果 |
| --- | --- | --- |
| 已提交 P0 基线 | `git archive HEAD` 到临时目录，控制面 venv 执行 `pytest -q -rs --ignore=tests/test_real_engines.py tests/` | **146 passed，36.15s** |
| 当前工作区控制面回归 | `./scripts/test.sh -q -rs --ignore=tests/test_real_engines.py` | **230 passed，40.53s** |
| 当前工作区真实引擎测试 | 经 `scripts/test.sh` 配置引擎 PATH，单独选择 `tests/test_real_engines.py` 对应测试 | **7 passed，20.86s** |

因此当前工作区的测试套件分两组执行，共 **237 项通过、无跳过**。相比 Claude 最后报告的“230 passed / 7 skipped”，本次补跑了可用的真实引擎测试。七项主要覆盖 SkillSpector/Cisco 的安装与真实扫描，以及目标形态校验，**不包含**五种引擎的全量真实调用、供应商实网 Probe、真实 Hook 或端到端 P1 验收。

## 8. 需要注意的文档差异

1. `ARCHITECTURE.md`、ADR 0004/0005 中的 FastAPI/SQLAlchemy 与实际标准库 HTTP + SQLite 原生 SQL 不一致，应区分目标技术栈与当前实现。
2. `DATA_MODEL.md` 和 `docs/architecture.zh-CN.md` 仍有“只有 scans/findings”的旧描述；P0 代码/现存库已经是 DetectorRun/RawReport/Finding，P1 工作区又新增执行相关表。
3. `ARCHITECTURE.md`、`UPSTREAMS.md` 和原型架构文档部分段落仍说“无认证”；实际已实现控制台认证与 RBAC。
4. P1 协议文档提及尚不存在的 `endpoint/protocols/`，API 注释也预述设备上报路径，不能将这些描述当成已交付端点。
5. P1 原计划仍保留“在本机安装 Hook”的早期执行说明；其后用户明确要求测试机执行，后者优先。部分 S2 测试要点也预写了 `verified`，而当前代码正确保持 `unverified`，须待 S3 证据才能升级。
6. 源计划的“revert 即净身”需要在真实数据库回滚方案中细化：撤回代码不会自动删除已创建的 v5 表、索引或新增列。
7. 计划中对 Hook 启动延迟的“毫秒级”描述尚无本项目实测支持，应在端侧实现后测量，不能作为已达到的性能指标。

本次以新增接手说明保留差异，没有批量重写既有架构或业务契约。

## 9. 建议接续顺序

1. 先按第 5 节对照 P0 验收矩阵，补供应商实测、真实引擎覆盖、部署配置、证据和回滚材料；把失败、候选和未验证项如实记录。
2. 审查 S1/S2 的未提交改动及原计划偏差，依据已有提交授权整理四条提交；不把 S3 录制脚本或本次文档误混进不对应的切片。
3. 在测试机确认产品版本、账号和现有 Hook；按用户边界完成 S3 的备份、录制、字段比对、恢复，形成脱敏 fixture 与产品执行回执。
4. 协议明确后按 S4 → S5 → S6 → S7 实现摄入、端侧、时间线和联调；任何 Codex 未验证能力继续明确标注。
5. P1 验收完整覆盖四项：版本化协议及 allow/confirm/block；Execution/Intent 关联与幂等；离线降级和未验证标识；prompt/密钥/环境变量不上传。
6. P1 主链路验收后再进入 P2 的 Linux Audit、进程/文件/网络证据和可评估归因，随后推进 P3 的策略/准入/Incident 闭环。

当前结论：**P0 已有实现和回归基础，验收未收口；P1 完成了 S1/S2 的代码基础，S3 未完成，S4–S7 尚未开始。**
