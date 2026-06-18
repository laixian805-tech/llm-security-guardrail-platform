# 小白开发日志与面试准备

_从 0 到 LLM Security Guardrail Platform 的实现记录、面试问答和简历映射 · Last updated: 2026-06-17_

---

## 这份文档怎么用

这不是操作手册，而是给你面试、复盘和写简历用的“项目讲解底稿”。目标是让你能回答三类问题：

1. 这个项目从 0 到 1 到底做了什么
2. 为什么这样设计，而不是只写一个关键词过滤 demo
3. 简历上的每一句话对应项目里的哪个模块，哪些表述应该增强或改得更准确

一句话版本：

> 我把传统渗透测试里的“构造 payload -> 跑基线 -> 加防护 -> 复测 -> 写报告”迁移到 LLM Agent 场景，重点覆盖 prompt injection、RAG poisoning、tool output poisoning 和 unauthorized tool calling，并用 AutoDL 真实模型、Garak、本地 probes、LangGraph trace 和报告产物证明防护链路可复现。

---

## 从零开始做了什么

### 0. 先确定问题边界

最开始要解决的问题不是“做一个聊天机器人”，而是：

> 当 Agent 能读 RAG 文档、接收网页内容、执行工具调用时，攻击者可以把恶意指令藏在用户输入、外部文档或工具返回里，诱导模型越权调用高危工具。

所以项目先定义三类核心风险：

| 风险 | 场景 | 项目中的入口 |
| ---- | ---- | ------------ |
| Prompt injection / role takeover | 用户要求忽略系统规则、扮演管理员、泄露提示词 | `GuardrailPipeline`、本地 probes、Garak |
| RAG poisoning | 恶意文档被检索进上下文，变成模型看到的“指令” | `/rag/poisoning-demo`、RAG sanitizer |
| Tool calling abuse | 模型被诱导调用导出、审计、管理类工具 | `ToolGateway`、`/agent/run` |

为什么先做边界：面试时最怕项目听起来很大但没有安全对象。这里的对象很明确：Agent 决策链路里的不可信输入和工具权限。

### 1. 搭平台骨架

先搭 FastAPI 后端和 React 前端，把所有能力都收敛到同一个平台入口。

| 模块 | 做了什么 | 为什么 |
| ---- | -------- | ------ |
| FastAPI | 提供 `/chat`、`/rag/*`、`/agent/run`、`/eval/*`、`/experiments/*` | 安全评测需要 API 化，才能复现和自动化 |
| React/Vite | 仪表盘、报告、评测、模型状态展示 | 面试展示不能只看命令行，需要可视化入口 |
| ReportStore | 管理 JSON、Markdown、HTML、Graph Run 等产物 | 评测结论要能保存、打开、复盘 |

对应代码：

- `backend/app/api/main.py`
- `web/src/App.jsx`
- `backend/app/evals/report_store.py`

### 2. 做第一版护栏和本地 probes

接着实现 `GuardrailPipeline`，支持 `off`、`audit`、`enforce` 三种模式。

核心思路：

- `off`：模拟无防护 baseline
- `enforce`：真正阻断命中样本
- `audit`：只记录不阻断，方便调规则

本地 probes 覆盖：

- `direct_injection`
- `role_takeover`
- `long_context_hijack`
- `rag_poisoning`
- `tool_return_poisoning`
- `unauthorized_tool_call`

为什么这么做：传统安全测试不是只证明“能拦”，还要先证明“没防护时确实有风险”。所以必须有 baseline 和 guarded 两轮。

对应代码：

- `backend/app/guardrails/pipeline.py`
- `backend/app/evals/runner.py`

### 3. 做工具网关和 Tool Calling Agent 靶场

Tool Calling 的重点是：模型可以建议调用工具，但不能拥有最终权限。

项目里做了两层：

| 层 | 作用 |
| -- | ---- |
| `model_plan` | 模拟模型规划出一个工具调用 |
| `ToolGateway` | 按角色、工具等级、参数风险做最终授权 |

示例：

- public 用户不能调用 admin 工具
- public 用户不能导出 salary、audit logs 等敏感范围
- 即使模型输出了工具调用，也必须经过后端授权

后来又增强了：

- 场景参数
- 最大步数
- 工具白名单
- tool output poisoning mock
- 多步 `agent_trace`
- LangGraph `graph_run`

对应代码：

- `backend/app/agent/tool_agent.py`
- `backend/app/tools/gateway.py`
- `backend/app/agent/graph.py`

面试讲法：

> 我没有把模型拒答当权限边界，而是把模型计划和工具执行拆开。模型只能提出候选工具调用，真正能不能执行由后端 ToolGateway 根据角色、工具等级和参数策略决定。

### 4. 做 RAG 投毒靶场

RAG 风险的关键是：模型很容易把检索到的外部内容当成指令。

项目做了：

- 轻量 RAG 存储和检索
- 文档来源、信任等级、可见角色
- RAG poisoning demo
- web poisoning、multi-hop、long-tail hijack 等场景
- context sanitizer，把低信任来源的指令性内容隔离

为什么不一开始上复杂向量库：当前目标是安全链路闭环和可解释，不是做检索系统性能竞赛。先用 JSON 持久化和混合检索，便于审计和单测。

对应代码：

- `backend/app/rag/service.py`
- `backend/app/rag/poisoning_demo.py`
- `backend/app/rag/sanitizer.py`

面试讲法：

> RAG 防护不是简单丢弃所有外部文档，而是给来源分级。低信任来源可以被检索到，但其中的指令性内容不能直接进入模型上下文，并且会写入审计。

### 5. 做正式评测闭环和报告

项目继续从 demo 走向“可复现实验”：

```text
攻击样本 -> baseline/off -> guarded/enforce -> ASR 对比 -> 失败样本分析 -> 下一轮 payload/防御建议
```

产物包括：

- `results.json`
- `results.csv`
- `report.html`
- `experiment-report.md`
- `experiment-report.html`
- `defense-feedback.json`
- `next-round-payloads.json`
- `candidate-guard-pack.json`
- `asr-comparison.json`
- `graph-run.json`

对应代码：

- `backend/app/evals/formal.py`
- `backend/app/evals/paired.py`
- `backend/app/evals/experiment_report.py`
- `backend/app/evals/defense_feedback.py`

面试讲法：

> 我没有只展示单个攻击样本，而是把测试变成闭环：同一批 payload 在护栏前后各跑一次，用 ASR 和失败样本解释防护效果。

### 6. 接入 Garak 和真实模型

后面接入 Garak 自动化红队扫描，并把模型推理放到 AutoDL。

部署形态：

| 机器 | 负责什么 |
| ---- | -------- |
| 腾讯云 | FastAPI、静态前端、报告、调度入口 |
| AutoDL | vLLM、Qwen3-8B、Mistral-7B、Garak runner |
| 本地隧道 | `127.0.0.1:18000 -> AutoDL 127.0.0.1:8000` |

为什么这样拆：

- 腾讯云轻量服务器不适合跑 7B/8B 模型
- AutoDL 适合 GPU 推理和长任务
- 后端统一走 OpenAI-compatible API，方便切换模型和接 Garak

对应代码和脚本：

- `backend/app/models/provider.py`
- `backend/app/evals/garak.py`
- `scripts/check-autodl-recovery.sh`
- `scripts/manage-autodl-models.sh`

### 7. 做动态防御包

项目加入 guard pack：

- preview：只校验规则，不启用
- activate：人工确认后启用
- active：查看当前规则
- deactivate：停用规则

安全边界：

- 只支持受限规则模板
- 不执行任意代码
- 不自动改源码

对应代码：

- `backend/app/guardrails/guard_packs.py`
- `backend/app/api/main.py`

面试讲法：

> 失败样本可以转成候选防御包，但不会自动上线。安全系统里自动修复很危险，所以我做的是半自动：生成建议、人工预览、受限模板激活。

### 8. 用 LangGraph 做可观测编排

最后把 Agent 和 security-cycle 内部流程包装成图节点。

Agent 节点：

```text
input_guard -> rag_retrieve -> model_plan -> tool_authorize -> tool_execute -> tool_output_guard -> output_guard -> report_trace
```

security-cycle 节点：

```text
load_regression_payloads -> formal_baseline -> formal_guarded -> write_report -> defense_feedback -> surface_asr -> candidate_guard_pack -> write_cycle_artifacts -> response_packaging
```

每个节点记录：

- 节点名
- 耗时
- 是否阻断
- 阻断点
- 输入摘要
- 输出摘要
- 错误
- metadata

为什么需要 LangGraph：

> Agent 安全问题很难只看最终回答，必须看决策路径。LangGraph 让每一步变成可观测节点，报告里可以解释攻击链在哪一步被切断。

对应代码：

- `backend/app/agent/graph.py`
- `backend/app/agent/tool_agent.py`
- `backend/app/api/main.py`

### 9. 企稳和发布

最后不再扩功能，而是做稳定性和发布检查。

已完成验证：

- 后端全量：`127 passed, 126 warnings`
- 前端测试：`23 passed`
- 前端 build：passed
- AutoDL `qwen3:8b` smoke：passed
- 最小真实 `security-cycle`：passed
- 真实六类 probe：`eval-673bef03` -> `eval-ac05b1e2`，6/6 guarded 阻断，ASR 从 100% 降至 0%
- 真实 coverage regression：`eval-dccb53e1` -> `eval-1d9e13c8`，18/18 guarded 阻断，ASR 从 100% 降至 0%，回归集 `coverage-expansion-v1`
- Mistral 对照回归：`eval-a0c2ac0c` -> `eval-caeb761f`，同一 `coverage-expansion-v1` 18/18 guarded 阻断，ASR 从 100% 降至 0%
- Benign false-positive gate：12 个正常业务/安全运维请求，误报率 0%
- GitHub 稳定基线已推送：`2a2df06 feat: stabilize guardrail security workflow`

---

## 面试官可能怎么问

### 你这个项目解决什么问题？

回答：

> 解决 AI Agent 在 Tool Calling 和 RAG 场景下被提示词注入、角色接管、外部文档投毒或工具返回投毒诱导，从而产生越权工具调用的问题。我把传统渗透测试的 payload 构造、基线压测、加固复测和报告产出迁移到了模型决策链路上。

### 为什么不是简单关键词过滤？

回答：

> 关键词过滤只能拦显式攻击，Agent 场景更复杂：攻击可能来自 RAG 文档、网页内容、工具返回，甚至是多跳检索后的组合。项目里把所有外部内容视为不可信源，结合来源分级、上下文清洗、工具网关和输出检测，而不是只看用户输入里有没有某个词。

### 你的护栏到底在哪里生效？

回答：

> 有多处。输入进入模型前有 input guard；RAG 检索结果进入上下文前有 sanitizer；模型计划调用工具后有 ToolGateway 授权；工具返回进入下一步前有 tool output guard；最终回答还有 output guard。现在 LangGraph 的 `graph_run` 可以展示每一步耗时和阻断点。

### 你怎么证明防护有效？

回答：

> 同一批 probes 跑两轮：`guard_mode=off` 作为 baseline，`guard_mode=enforce` 作为 guarded。通过 ASR、失败样本、规则命中、报告文件来比较。最新主链路把 6 类标准 probe 扩展到 18 个标准/回归样本，并在 Qwen3-8B 和 Mistral-7B 上分别完成真实对照，两个模型 guarded ASR 都降到 0%；同时用 benign preview 检查正常业务请求误报率，当前为 0%。

### Garak 在项目里起什么作用？

回答：

> Garak 是自动化 LLM 漏洞扫描器。我把它接到同一个 OpenAI-compatible API 上，让它测真实后端链路，而不是单独测裸模型。本地 probes 更适合稳定回归和解释，Garak 更适合扩展攻击覆盖面。

### Tool Calling 为什么要单独做网关？

回答：

> 因为模型输出不是权限边界。即使模型计划调用 `export_data`，也必须由后端根据 caller role、tool tier 和参数风险决定是否允许。这个设计类似传统后端鉴权：AI 可以参与决策，但不能绕过权限系统。

### RAG 投毒怎么处理？

回答：

> 检索出来不代表可以直接进上下文。我给文档设置来源和信任等级，低信任来源里的指令性内容会被 sanitizer 隔离，并写入审计。这样可以展示“投毒 chunk 被检索到了，但攻击链在进入模型上下文前被切断”。

### LangGraph 是不是只是包装？

回答：

> 它不改变业务安全边界，但让内部流程变成可观测节点图。以前只能看 `agent_trace`，现在报告里还有 `graph_run`，能看到节点顺序、耗时、阻断点和摘要。面试展示时可以解释模型决策路径，而不是只展示最终结果。

### 你有没有真正接 NVIDIA NeMo Guardrails？

建议诚实回答：

> 当前版本已经把 NeMo Guardrails runtime 作为主护栏引擎接入后端配置层，默认 `LLMSEC_GUARD_ENGINE=nemo`。为了保证平台在缺依赖或配置异常时仍可复现，我保留了 `custom_nemo` fallback 和原有动态 guard pack 规则层。也就是说，NeMo 负责输入/输出/对话策略 rail，ToolGateway 和 RAG sanitizer 仍然是项目自己的确定性安全边界。

更稳的简历写法是“引入 NeMo Guardrails runtime 作为主护栏引擎，并保留自研 ToolGateway、RAG sanitizer、动态 guard pack 与 LangGraph 可观测闭环”。不要写成“所有防护完全由 NeMo 实现”，因为工具授权和 RAG 来源隔离仍然是项目自研逻辑。

### 有没有用本地向量模型？

建议诚实回答：

> 当前 RAG 使用 JSON 持久化和轻量混合检索，重点是安全审计、来源分级和投毒隔离，没有把本地 embedding 模型作为必要依赖。后续可以把 Chroma、本地 embedding 或语义分类器并联到现有 sanitizer 前后。

如果简历写“基于轻量级本地向量模型”，最好改掉，除非后续真的接入 embedding 模型并有测试。

### 这个项目离生产还差什么？

回答：

> 还差认证、用户权限体系、速率限制、审计日志持久化、工具沙箱、真实业务工具隔离、更强的语义模型和更多长任务调度。当前定位是个人简历/研究型原型，重点证明安全闭环和工程能力，不把它包装成商业级安全平台。

### 如果护栏误杀怎么办？

回答：

> 所以支持 `audit` 模式和报告分析。规则先审计再 enforce；失败样本和误杀样本都进入下一轮 regression set。动态 guard pack 也必须 preview 后人工启用。

### 你项目里最有含金量的部分是什么？

回答：

> 第一是把 AI 安全问题做成了可复现实验闭环，不只是聊天 demo；第二是 ToolGateway 把模型计划和工具权限分离；第三是 RAG sanitizer 和 LangGraph trace 能解释攻击链在哪一步被切断；第四是接了 AutoDL 真实模型和 Garak，而不是只用 stub。

---

## 简历原文逐条映射

下面按你现在的简历描述逐条看：哪些已经对应，哪些需要改得更准确。

### 1. 项目描述

原文：

> 面向 Agent Tool Calling 场景下的提示词注入、角色接管与越权工具调用风险，将传统渗透测试思路与 AI 护栏结合，设计并实现一套模型决策路径构建越权检测与拦截原型。

评价：准确，而且现在可以增强。

项目对应：

- Tool Calling Agent：`backend/app/agent/tool_agent.py`
- ToolGateway：`backend/app/tools/gateway.py`
- LangGraph 决策路径：`backend/app/agent/graph.py`
- Agent trace / Graph Run：`agent_trace`、`graph_run`

建议改成：

> 面向 Agent Tool Calling、RAG 检索与工具返回链路中的提示词注入、角色接管和越权工具调用风险，将传统渗透测试的 payload 构造、基线压测、加固复测迁移到 LLM Agent 决策路径，设计并实现一套支持 LangGraph trace、工具网关授权和报告审计的拦截原型。

### 2. 多维漏洞挖掘

原文：

> 围绕直接/间接注入与越狱攻击构造多维度攻击样本，覆盖角色接管长文本注意力稀释，以及 RAG 文档投毒、网页内容投毒、工具返回投毒等典型场景，系统性模拟 Agent 在复杂交互链路下的安全风险。

评价：准确，现在项目已经覆盖得更完整。

项目对应：

- 本地 probes：`backend/app/evals/runner.py`
- RAG poisoning scenarios：`backend/app/rag/poisoning_demo.py`
- Tool output poisoning：`backend/app/agent/tool_agent.py`
- 回归 payload：`defense-feedback` 和 `next-round-payloads.json`

建议补一个“可复现”：

> 构造 direct injection、role takeover、long context hijack、RAG document/web poisoning、tool return poisoning、unauthorized tool call 等多维攻击样本，并沉淀为可回归 probes 与下一轮 payload。

### 3. 自动化红队扫描

原文：

> 基于 Garak 自动化漏洞扫描器对基线模型开展提示词攻击压测，并结合自定义 payload 补充工具调用场景测试，形成“攻击样本构造-基线压测-护栏复测”的评测闭环。

评价：准确。

项目对应：

- Garak adapter：`backend/app/evals/garak.py`
- 自定义 payload：`backend/app/evals/runner.py`
- formal/security-cycle：`backend/app/api/main.py`
- 报告：`backend/app/evals/experiment_report.py`

可以增强：

> 接入 Garak、Promptfoo 适配层和本地 probes，统一输出 JSON/CSV/HTML/Markdown 报告，支持 baseline/off 与 guarded/enforce 成对对比。

### 4. 语义级防御设计

原文：

> 基于 NVIDIA NeMo-Guardrails 与轻量级本地向量模型构建语义防护链路；将用户输入及外部内容统一视为不可信源，在进入上下文前完成来源分级、语义检测与策略隔离。

评价：NeMo 部分现在可以增强；“轻量级本地向量模型”仍然不要写死，除非后续真的接入 embedding 模型并有测试。

更稳写法：

> 引入 NVIDIA NeMo Guardrails runtime 作为输入/输出策略 rail，并保留自研 RAG context sanitizer、ToolGateway 授权和动态 guard pack fallback；将用户输入、外部文档、网页内容和工具返回统一视为不可信源，在进入模型上下文或工具执行前完成来源分级、指令隔离和策略拦截。

如果后续接入 embedding 或独立安全分类器，再补“轻量级本地向量模型/语义分类器”。

### 5. 项目成果

原文：

> 基于 Garak 对基线模型实测，典型逻辑注入与长文本劫持场景下攻击成功率分别达 65% 和 80%；接入护栏后，直接注入与间接注入样本均得到有效拦截，高危工具调用风险显著下降。

评价：需要换成当前项目可证明的数据，除非你保留了对应 65%/80% 的正式报告。

当前更好写法：

> 在 AutoDL 上接入 Qwen3-8B 与 Mistral-7B 进行真实评测；最新 `security-cycle` 使用同一 `coverage-expansion-v1` 覆盖 6 类标准 probe 和 12 个 coverage regression 变体，两个模型 baseline ASR 均为 100%，接入 NeMo Guardrails 主护栏、RAG sanitizer 与 ToolGateway 后 guarded ASR 均降至 0%，并自动生成 Markdown/HTML/JSON/Graph Run 报告用于复盘。

如果觉得 100% baseline 听起来太绝对，也可以保守写：

> 在最新 security-cycle 中，典型攻击集护栏前 ASR 明显高于护栏后，接入防护后 Qwen3-8B 与 Mistral-7B guarded ASR 均降至 0%，RAG 投毒和越权工具调用链路均可在报告中追踪阻断点。

---

## 建议放到简历里的版本

项目名：

> LLM Agent 安全护栏与自动化红队评测平台

简历 bullet 推荐：

```text
- 面向 Agent Tool Calling、RAG 检索与工具返回链路中的提示词注入、角色接管和越权工具调用风险，设计并实现 FastAPI + React 的 LLM 安全护栏与自动化红队评测平台。
- 构造 direct injection、role takeover、long context hijack、RAG/web poisoning、tool return poisoning、unauthorized tool call 等攻击样本，接入 Garak 与本地 probes，形成 baseline/off 与 guarded/enforce 成对复测闭环。
- 引入 NeMo Guardrails runtime 作为主护栏引擎，保留 `custom_nemo` fallback、RAG context sanitizer、ToolGateway 授权和动态 guard pack 预览/启用机制，将用户输入、外部文档和工具返回统一视为不可信源处理。
- 引入 LangGraph 将 Agent 与 security-cycle 编排为 input_guard、rag_retrieve、model_plan、tool_authorize、tool_execute、tool_output_guard、output_guard 等可观测节点，报告中输出节点耗时、阻断点和输入输出摘要。
- 在 AutoDL vLLM 上完成 Qwen3-8B 与 Mistral-7B 真实评测；最新 security-cycle 中两个模型的 18 个标准/回归攻击样本 ASR 均从 100% 降至 0%，并生成 Markdown/HTML/JSON/Graph Run 报告用于复盘和下一轮防御迭代。
```

如果简历版面有限，可以压缩成三条：

```text
- 设计并实现面向 LLM Agent Tool Calling/RAG 场景的安全护栏平台，覆盖 prompt injection、role takeover、RAG/web poisoning、tool output poisoning 和 unauthorized tool call。
- 接入 Garak、本地 probes、AutoDL vLLM 与 LangGraph trace，形成“攻击样本构造 -> baseline 压测 -> guarded 复测 -> ASR/失败样本/报告输出”的闭环。
- 基于来源分级、RAG context sanitizer、ToolGateway 授权和动态 guard pack 拦截高危链路；Qwen3-8B/Mistral-7B 最新 18 样本 security-cycle 中 ASR 均从 100% 降至 0%，12 个 benign 样本误报率为 0%。
```

---

## 哪些已经增强，可以写进简历

| 能力 | 现在是否能写 | 证据 |
| ---- | ------------ | ---- |
| Tool Calling Agent 靶场 | 可以 | `/agent/run`、`agent_trace`、`graph_run` |
| RAG 文档/网页/长尾投毒 | 可以 | `/rag/poisoning-demo` 多场景 |
| Tool output poisoning | 可以 | `inject_tool_output`、`tool_output_guard` |
| 动态防御包 | 可以 | `/guard-packs/preview`、`activate`、`active`、`deactivate` |
| LangGraph 可观测编排 | 可以 | `backend/app/agent/graph.py`、`graph-run.json` |
| AutoDL 真实模型 | 可以 | Qwen3-8B、Mistral-7B、vLLM、隧道 |
| Garak 自动化扫描 | 可以 | Garak adapter 和 AutoDL reports |
| 两模型矩阵 | 可以 | `qwen3:8b` + `mistral-7b` |
| 报告中心 | 可以 | Markdown/HTML/JSON/Graph Run artifacts |

---

## 哪些不要写太满

| 表述 | 风险 | 推荐替代 |
| ---- | ---- | -------- |
| “生产级安全平台” | 当前没有完整认证、租户隔离、工具沙箱 | “研究型/简历级安全评测原型” |
| “所有防护都基于 NVIDIA NeMo-Guardrails” | 夸大；ToolGateway/RAG sanitizer/动态规则仍是自研边界 | “引入 NeMo Guardrails runtime 作为主护栏引擎，并保留自研确定性安全边界” |
| “基于本地向量模型” | 当前没有强依赖 embedding 模型 | “轻量混合检索与上下文清洗，后续可接 embedding” |
| “自动修复漏洞” | 动态防御包不会自动改源码 | “生成候选防御包，人工预览后启用” |
| “支持 3+ 模型矩阵” | 当前因磁盘只保留两模型 | “已支持 Qwen3-8B/Mistral-7B 两模型矩阵，3+ 模型预留” |
| “完全阻断所有注入” | 任何安全系统都不能这么写 | “显著降低 ASR，并保留失败样本用于回归” |

---

## 30 秒口述稿

> 这个项目是一个面向 LLM Agent 的安全护栏和自动化红队评测平台。我把传统渗透测试中的 payload 构造、基线压测、加固复测和报告输出迁移到 Agent Tool Calling/RAG 场景，覆盖 prompt injection、RAG 投毒、工具返回投毒和越权工具调用。系统通过输入输出检测、RAG context sanitizer、ToolGateway 授权和 LangGraph trace 记录攻击链阻断点，并在 AutoDL 上用 Qwen3-8B/Mistral-7B 做真实评测，最终生成 Markdown/HTML/Graph Run 报告。

## 2 分钟口述稿

> 我做这个项目的原因是，Agent 不只是聊天模型，它会读外部文档、调用工具、根据工具返回继续决策，所以传统 prompt injection 的影响会扩展到权限和数据安全。我先构造了 direct injection、role takeover、long context hijack、RAG poisoning、tool return poisoning 和 unauthorized tool call 这些攻击样本，然后做 baseline/off 和 guarded/enforce 两轮评测，用 ASR 和失败样本证明护栏前后的差异。
>
> 防御上，我没有只做关键词过滤，而是把所有用户输入、RAG 文档、网页内容和工具返回都当成不可信源。输入先过 guardrail，RAG 内容进入上下文前做来源分级和 sanitizer，模型提出工具调用后必须经过 ToolGateway 的角色、工具等级和参数策略检查，工具返回和最终输出也会再过护栏。
>
> 工程上，后端是 FastAPI，前端是 React，真实模型放在 AutoDL 上通过 vLLM 提供 OpenAI-compatible API，腾讯云只做平台入口和报告中心。后来我用 LangGraph 把 Agent 和 security-cycle 拆成可观测节点，报告里能看到每个节点耗时、阻断点和输入输出摘要。最新 Qwen3-8B/Mistral-7B 18 样本 security-cycle 中攻击集 ASR 都从 100% 降到 0%，并且 RAG 投毒和高危工具调用都有可追踪的拦截证据。

---

## 面试前自检清单

面试前至少确认：

| 检查项 | 命令或入口 |
| ------ | ---------- |
| 后端健康 | `GET /health` |
| 前端可打开 | `http://43.139.77.64:8000/` |
| 当前默认模型 | `/health` 显示 `qwen3:8b` |
| Agent trace | `POST /agent/run` |
| RAG 投毒 demo | `POST /rag/poisoning-demo` |
| Graph Run artifact | `GET /report-files/<run_id>/graph_run` |
| 最新报告 | `model-matrix-20260617-1746-qwen-mistral` |
| GitHub 最新提交 | `git log --oneline -1` |

如果现场不能联网，就讲架构、报告截图和 README；如果能联网，再打开前端和报告中心。
