# qwen-code 端侧闭环（2026-11-12）

上午只做到适配器与协议 spike，产品实际跑在主机 a 的隔离 HOME + mock 模型上。本轮把它接进测试端 b 的真实链路：真实 CLI、真实 StepFun 模型、真实端侧 hook、真实控制面纳管。

## 结果：一条完整证据链

| 环节 | 结果 |
| --- | --- |
| 端侧安装 | `~/.qwen/settings.json` 挂 SessionStart/PreToolUse/PostToolUse，命令走 `endpoint.hook qwen-code` |
| 协议解析 | 0.26.8 抓包与 0.27.2 字段集一致，同一适配器解析通过 |
| 阻断 | deny 用例：`/tmp/qwen-x-e2e-deny.txt` **不存在**；qwen 自报 `Tool "run_shell_command" was not run: ASGP endpoint rule` |
| 放行对照 | allow 用例：文件**存在** |
| 控制面上报 | `sent=3 dead=0`；`executions` 出现 `qwen-code / 0.26.8` |
| 决策落库 | `intents` 有 `decision=deny, hook_event_type=pre_tool_use, reason="ASGP endpoint rule"` |

首次实现里 PreToolUse 的 intent 全部被拒（`http_400`），根因见下。

## 三个真问题（都已修）

### 1. 产品白名单与注册表脱钩

`ingestion_service.execution()` 硬编码 `if data.product not in ("codex","claude-code")`。`registry.py` 的 docstring 写着"增删产品只改这里的注册表，不改摄入与查询服务"——代码没兑现。加 qwen 后控制面仍 400 拒收执行记录。

改为 `ProductCatalog().ids()`。这是一次"承诺与实现不一致"的典型案例：文档说只改一处，实际要改两处，第二处还藏在 service 里。

### 2. 版本门控把设备实版本挡在外面

控制面声明 `qwen-code 0.27.2`（spike 版本），设备实为 **0.26.8**，`ingest.intent()` 的版本门控要求 `descriptor.product_version == execution.product_version`，于是所有带决策的 PreToolUse 记录被拒 → 只有 PostToolUse（decision=not_applicable，不触发门控）能进库。

处理：声明版本改为设备实版本 0.26.8，并把 0.26.8 的三事件抓包归档为 fixture；0.27.2 的抓包保留，测试参数化跑两版，证明**协议形状一致但门控仍按实版本**。

### 3. 端侧只记 HTTP 状态码，记不到服务端的错误码

outbox 的 `last_error` 只有 `http_400`，看不到服务端返回的 `unsupported_decision`，排查时只能靠服务层复现。这是可观测性缺口：4xx 的响应体里明明有 `{"error":{"code":...}}`，端侧没保存。

## 一个方法论教训：402 不是额度耗尽，是端点打错

我先用 `https://api.stepfun.com/v1/chat/completions` 探测，得到 `402 quota_exceeded`，据此判断"额度耗尽、真实模型跑不了"，停掉了 Qwen 实测，还写进了记忆和验收记录。

实际配置的端点带路径前缀：`https://api.stepfun.com/step_plan/v1`。三个端点的对照：

| 端点 | 结果 |
| --- | --- |
| `/v1/chat/completions`（无 step_plan） | **402 quota_exceeded** |
| `/step_plan/v1/chat/completions` | 200 |
| `/step_plan/v1/messages`（Anthropic 兼容） | 200 |

b 上 `.qwen/settings.json` 的 `baseUrl` 也少了 `/step_plan`，所以它同样会 402——这个错误配置本身也解释了"为什么 qwen 一直跑不通"。

教训与 attack-set 那轮的 `exit 1` 同类：**错误码的字面意思不等于真实原因**。402 可能来自套餐、也可能来自路由；判"额度耗尽"前必须换一个已知可用的端点做对照。

## 现场状态

- `fail_mode` 已恢复 `observe`，临时 `deny_patterns` 已清空；`verified_decisions['qwen-code'] = '0.26.8'`。
- 采集服务仍是按需启停（`inactive`），没有恢复常驻。
- 全量回归 **378 passed**。
- qwen 在 b 上会被 OOM kill（1.7G 内存机器跑 node + qwen 峰值偏高）；数据在 kill 前已写入 outbox，不影响证据，但连续跑要留意。
