# 旧平台模块审计与 ASGP 映射

**审计范围：** 只读检查 `/root/llm-security-guardrail-platform`，不迁移或修改旧仓库代码。当前旧仓库 `backend/app/agent_security/` 共约 8,733 行 Python；`store.py` 单文件约 1,785 行。ASGP 是新项目，下面的映射用于决定“吸收概念、复用接口、重写边界”，不是把旧目录整体复制过来。

## 模块映射

| 旧平台模块 | 已有能力/经验 | ASGP 目标位置 | 处理方式 |
| --- | --- | --- | --- |
| `models.py`、`asset_identity.py` | Asset kind/carrier、logical/instance ID、内容 Hash、安装/启用/运行状态分离 | `domain/asset`、Asset/AssetInstance/AssetRelease | **吸收概念并重建 Schema**；保留逻辑身份与实例身份分离，扩展为正式关系模型 |
| `scanner.py`、`rules.py`、`assessment.py` | Skill/MCP 静态规则、SARIF/扫描报告、风险 breakdown | `adapters/detectors`、DetectorRun/Finding | **保留为可选 Detector**；检测器不再直接写业务库，全部通过 Detector Adapter 和 Finding Normalizer |
| `adapters.py`、`hook.py`、`guard.py` | Claude/Codex Hook 协议差异、前置决策、能力矩阵、trust/governance 信息 | `adapters/agents`、Hook Collector、Product Capability Matrix | **逐产品逐版本重建适配器**；保留协议核验方法，只有实测支持的产品/版本才声明 deny 能力 |
| `collector.py`、`monitor.py` | Linux Audit 解析、`/proc` 进程快照、进程树、文件/网络事件和初步关联 | `collectors/linux_audit`、Execution/RuntimeEvent/Attribution | **吸收实验和事件字段，重构采集链**；补本地 outbox、事件丢失指标、来源与归因置信度；先 Audit 后评估 eBPF |
| `admission.py`、`policy.py` | 解释型 admission checks、Allow/Ask/Block 结果、Hook 拦截语义 | `governance/policy`、`governance/admission` | **复用决策思路，重做事务边界**；旧 `evaluate_path()` 是检查，不等于真实 install/enable 的 stage/commit/verify/rollback |
| `model_layer.py`、`api/main.py` | 模型层 decision/eval event 与运行时事件进入同一时间线；通用 OpenAI-compatible chat provider | `providers`、Execution/Event API、Detector Provider Port | **吸收统一时间线和通用协议适配思想**；StepFun 主用，讯飞候选；不迁移旧的大型 API 工厂函数 |
| `threat_intel.py`、`ti.py` | IOC 抽取、查询预算、缓存和外部情报状态 | `enrichment/threat_intel`（后续） | **后置集成**；不能让外部声誉服务决定原始 Finding 是否存在或覆盖运行时证据 |
| `store.py` | 单 SQLite 表承载资产、事件、扫描、设备、风险等状态 | `storage/repositories` + Postgres schema | **不搬运现有表结构**；先拆领域实体，定义迁移和审计边界，避免继续扩大“万能 Store” |
| `guardrails/`、`rag/`、`tools/`、评测和报告模块 | LLM 输入输出护栏、RAG、ToolGateway、红队评测和报告生成 | 与 ASGP 相邻的模型安全/评测系统 | **不并入 ASGP 核心域**；可通过独立 API/报告接入，不能和 Agent 运行时资产、Incident 混成一个数据模型 |
| `web/src/pages/` | 资产、运行时、模型层、策略和报告的信息架构 | ASGP React/TypeScript Console | **参考页面分区，重建前端契约**；不迁移旧前端模型或旧 API 假设 |

## 吸收的原则

1. 逻辑资产、实例、来源、载体、内容 Hash、安装/启用/运行状态必须分开。
2. 静态 scanner verdict、Finding、Risk Assessment、Policy Decision 和 Enforcement Evidence 是不同记录。
3. Hook/Collector 事件需要共享 Execution/session 维度，但事件不能仅靠时间窗口强行归因。
4. Claude Code、Codex 和其他 Agent 产品的 Hook 生命周期及阻断能力按版本声明。
5. Provider API 使用协议适配：旧代码有通用 Chat Completions Provider，但 StepFun Codex Profile 是 Responses，不能把两种 wire API 当成同一种。

## 不迁移的主要原因

- 旧 `AgentSecStore` 适合此前的快速原型，不是 ASGP 六实体及事件归因模型的持久化契约。
- 当前 admission gate 返回决策，但并不控制第三方安装动作，也不具备完整提交验证和补偿事务。
- 旧 collector 有 Audit 与 `/proc` 解析实验，但不能据此宣称所有 Agent 产品都能因果归因或可靠阻断。
- 旧项目还承担聊天护栏、RAG、模型评测、报告和 Agent 安全治理等多个不同边界；ASGP V1 只围绕 Agent 资产、运行时证据、归因与治理闭环。

因此旧平台定位为**概念与可复用模块的参考实现**。每个准备迁移的模块都必须先通过 P0/P1 契约和验收，不能按文件数量搬运。
