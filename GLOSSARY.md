# ASGP 安全治理领域

本词汇表描述 ASGP 如何表示 Agent 资产、安全证据、运行行为和治理处置。术语用于跨 Agent 产品、扫描器和运行时采集器保持一致。

## 资产与检测

**Asset（资产）**：纳入治理范围的 Agent、Skill、MCP Server、插件或工具。资产的逻辑身份、安装实例和内容版本是不同维度。

**Logical Asset（逻辑资产）**：跨主机、安装路径和产品实例代表同一治理对象的身份，通常由产品、类型和规范名称确定。
_Avoid_: 文件路径就是资产身份

**Asset Instance（资产实例）**：一个逻辑资产在特定产品、主机和作用域中的具体安装或发现副本。
_Avoid_: 逻辑资产、内容版本

**Asset Release（资产版本）**：一个可验证发布版本，绑定发布者、版本号、来源和内容哈希。
_Avoid_: 扫描快照

**Asset Provenance（资产来源）**：资产从何处以及通过什么渠道进入环境的证据。来源可信度与内容风险分开评估。
_Avoid_: 已安装即可信

**Asset Carrier（资产载体）**：资产实例所在的产品内置目录、市场缓存、用户目录、项目目录或供应链依赖等位置类别。载体描述位置和范围，不代表可信度。
_Avoid_: 来源结论、风险等级

**Installation State（安装状态）**：资产实例是否缓存、安装或移除。
_Avoid_: 启用状态、运行状态

**Activation State（启用状态）**：产品配置中资产实例是否被启用或禁用；它不证明资产已被加载或运行。
_Avoid_: 活跃状态

**Runtime State（运行状态）**：Hook 或操作系统证据观察到的实例状态，例如空闲、活跃或已终止。
_Avoid_: 安装状态、扫描结论

**Detector（检测器）**：对资产或行为执行一种有版本、可声明能力的分析器。检测器输出原始结果和标准化 Finding，不直接修改资产状态或执行治理动作。
_Avoid_: 直接写业务表的扫描脚本

**Finding（发现项）**：检测器基于规则和证据产生的一条观察结果。Finding 可以误报；它本身不是 Incident，也不是最终风险裁决。
_Avoid_: 已确认恶意

**Scanner Verdict（扫描器判定）**：一次扫描按引擎动作规则返回的 clean、alert 或 block 结果。它描述扫描策略动作，不等于对资产恶意性的最终裁定。
_Avoid_: Risk Assessment、confirmed malicious

**Evidence（证据）**：支持 Finding 或 Attribution 的具体材料，例如文件位置、进程关系、网络目标或 Hook 字段，并记录来源与完整性。
_Avoid_: 只有分数没有依据

**Risk Assessment（风险评估）**：根据 Finding、来源、运行时证据和人工复核形成的当前风险判断，包含置信度和理由。
_Avoid_: 原始扫描分数、策略动作

**Confirmed Malicious（确认恶意）**：由授权分析员或足够权威且高置信的证据确认的结论。单条静态 Finding、未登记来源或哈希变化都不能单独证明恶意。
_Avoid_: suspicious、high-risk candidate

## Agent 执行与行为

**Execution（执行）**：一次 Agent 任务或会话的边界，记录产品、主机、开始/结束时间和关联资产。它不是操作系统进程。
_Avoid_: PID、用户自然语言意图

**Intent（操作意图）**：Agent 适配器观察到的一次具体操作请求，通常是 Tool Call 或产品 Hook 事件。没有足够证据时，不从用户文本推断 Intent。
_Avoid_: 对用户目的的心理推断

**Runtime Event（运行时事件）**：Hook、Audit 或内核采集器观察到的实际行为，例如进程启动、文件访问或网络连接。事件允许保持未归因状态。
_Avoid_: Intent、策略决定

**Attribution（行为归因）**：基于证据将 Intent、进程和 Runtime Event 关联起来的判断，必须记录方法、置信度和证据。一个事件可以有多个候选关联，也可以没有关联。
_Avoid_: 仅凭时间接近就认定因果关系

**Enforcement Evidence（执行生效证据）**：证明策略位于产品实际执行路径且产品遵守 Allow、Confirm 或 Block 决定的记录。
_Avoid_: 页面显示了策略、采集器发现了事件

## 治理

**Policy Decision（策略决定）**：策略引擎对一个明确请求给出的 Allow、Audit、Confirm 或 Block 结果。策略决定与 Finding 和风险评估分开保存。
_Avoid_: 检测器直接拦截

**Admission（准入）**：资产安装、启用或加载前的一次有状态治理流程，包含检查、审批、提交、验证和必要的补偿/回滚。
_Avoid_: 只生成扫描报告

**Incident（安全事件工单）**：供分析员调查和处置的一组 Finding、Runtime Event 与 Attribution，不等同于单条告警。
_Avoid_: Finding、原始事件流

**Detector Adapter（检测器适配器）**：把某个上游检测器的输入、版本、运行模式和原始输出接入 ASGP 统一契约的边界组件。
_Avoid_: 复制一份上游规则库

**Model Provider Profile（模型供应商配置）**：描述供应商、基础地址、模型 ID、协议类型和密钥引用的配置，不包含明文密钥。
_Avoid_: 把模型供应商硬编码进检测器

**Wire API（接口协议）**：模型服务的具体请求协议，例如 OpenAI Responses 或 Chat Completions。相同供应商可能同时提供不同协议。
_Avoid_: 只看供应商名称就假定接口兼容
