# ASGP 实施计划与验收标准

**目标：** 按依赖顺序把扫描器集成原型演进为 Agent 安全治理平台。每个阶段可单独部署、验收和回滚；未实现的功能不得在 UI、API 或演示中标记为完成。

## P0：领域契约、检测器与供应商 API

**范围**

- 建立模块化单体代码骨架：`api/`、`domain/`、`services/`、`adapters/`、`detectors/`、`collectors/`、`policies/`、`storage/`、`workers/`。
- 把 ASGP 的 Asset、Finding、DetectorRun、ProviderProfile Schema 固定为 Pydantic 和 JSON Schema 契约。
- 将当前 `scans/findings` 原型迁移为 DetectorRun/RawReport/标准 Finding，保留上游版本、规则 ID、raw report 和 fingerprint。
- 通过 Detector Adapter 运行 SkillSpector、Cisco MCP Scanner、A.I.G Skill/MCP Scanner、Snyk Agent Scan；每个 CLI 子进程有超时、输出限制和最低权限。
- StepFun 设为主用 Provider；保留讯飞候选；明确区分 Codex Responses 与 A.I.G Chat Completions profile。Probe 失败的 provider 不进入默认路由。
- Provider Profile 读取 Codex 配置中的 endpoint/wire metadata 和 provider-specific Authorization header；StepFun/讯飞 key 可分别由环境变量覆盖，配置头只在内存读取。任何密钥均不回传或持久化。
- 加控制台认证、Provider Secret 管理、请求审计和扫描数据保留策略后，才允许公网部署。

**验收**

- 对每个 DetectorAdapter 执行一致的契约测试：成功、无发现项、部分结果、超时、错误退出、无效 JSON、输出超限。
- 输入 SARIF 2.1.0 或上游 JSON 后可以查询标准 Finding；原始报告可按权限复核，列表 API 不泄露整段源文件。
- 只切换 detector 配置即可增加/移除扫描器，不改 Asset/Finding 服务。
- StepFun 和讯飞分别做 API Probe；验证响应协议、模型 ID、超时、错误映射和所需结构化/工具调用能力。API Key 不进入日志、数据库和进程 argv。
- 同一目标重试不会产生重复 DetectorRun/Finding；扫描器超时不被显示为 clean。
- 外部访问未认证时返回 401/403；设备身份和控制台用户权限分离。

## P1：多产品接入与 Hook 执行上下文

**范围**

- 建立 AgentProductAdapter 接口和产品/版本 capability matrix。
- 首批实现 Claude Code 与 Codex：SessionStart/End、PreToolUse/PostToolUse；将产品字段映射为 Execution 和 Intent。
- 每个 Hook 明确声明 `observe`、`confirm`、`deny` 能力；按具体产品版本验证，不支持的能力标为 unsupported。
- Agent 端实现本地脱敏与 outbox；控制面提供 enrollment、设备令牌吊销和批量上报。
- 策略判断只在 Hook 真的位于执行前时返回阻断；未验证产品回执时不登记 EnforcementEvidence。

**验收**

- 每个支持版本的 Hook fixture 有 allow/confirm/block 三类协议测试和字段兼容测试。
- 一个真实或可复现的 Codex/Claude 执行能关联到 Execution 和 Intent；重复上报幂等。
- Hook 服务离线时按产品能力策略降级；行为在报告中标注为未验证，而不是宣称已拦截。
- 端点不上传原始 prompt、完整密钥参数或环境变量；日志包含 request/event ID 但不包含秘密。

## P2：Linux 运行时采集与行为归因

**范围**

- V1 运行环境先限定 Linux。
- 先用 Linux Audit 采集进程创建、文件访问和网络连接；inotify 只作为文件变化补充，不声称能观察完整文件读取。
- Runtime Collector 将事件写入端点本地持久 outbox，批量、重试、去重后上报。
- Attribution Service 建立 `EventAttribution`，至少支持 Hook ID 精确关联、进程树关联、时间/资源特征弱关联。
- 允许事件未归因、多个候选归因和冲突；每条关联保存 method、confidence、evidence_refs 和规则版本。
- 不引入自研 eBPF 探针；只有 Audit 覆盖缺口和性能数据明确后再评估 eBPF。

**验收**

- 有标注的攻击/正常 trace 集可重复回放，分别统计事件采集覆盖率、丢失率、归因 Precision/Recall。
- 已知 Tool Call → Process → Network 样本能还原时间线；无 Tool Call 的后台进程保留为未归因，不硬连到最近 Intent。
- 采集器权限、CPU/内存上限、队列最大容量和磁盘保留策略有实测结果。
- Collector 停止或断网期间数据可排队；恢复后事件 ID 不重复。

## P3：风险决策、准入和 Incident 闭环

**范围**

- 风险评估分开计算 Intrinsic Risk、Runtime Risk、Exposure Risk，并保留每项证据、置信度和来源；不能简单相加不同引擎的分数。
- Policy Decision 使用统一 Allow/Audit/Confirm/Block 接口；Detector 不直接修改资产状态。
- 对 Skill/MCP 安装先实现单一、可验证的 Admission 状态机：check → approve → stage → commit → verify → reconcile/rollback。
- 建 Incident 与 IncidentEvidence，支持调查、确认误报/真实风险、修复、复测、关闭和重新打开。
- Console 实现 Asset Center、Detection Center、Runtime Explorer、Incident Center、Policy Center。

**验收**

- 一条恶意 Skill 流程可从扫描 Finding 追踪到 admission 拦截、关联运行事件、Incident 处置和复测关闭。
- 安装失败、审批超时、审批后内容哈希改变和重复 commit 都有确定且幂等的状态转移。
- 运维指标使用真实数据：误报率、归因准确率、拦截成功率、MTTR、复测通过率；基准测试同时报告安全 ASR 和任务 Utility。
- 分析员操作、策略版本、审批人、回滚和复测记录可审计。

## 后续阶段：跨平台与规模扩展

在 Linux 主链路数据可信之后，再增加 Windows/macOS Collector、评估 OPA、按实际写入量迁移 PostgreSQL、拆分 Collector/Worker。Kafka、Redis、图数据库和 eBPF 都以测得的瓶颈或能力缺口为前提，不作为 V1 默认依赖。

## 阶段门槛

每个阶段结束时必须提交：功能清单、自动化测试结果、版本/配置、已知限制、数据迁移/回滚方案和运行证据。未达到验收项时保留为候选，不标记为“已纳管”或“已阻断”。
