# Agent Security P5 可重复验收台

_目的：把 P0–P4 的实现状态转成可复跑、可审查的本地证据 · 2026-11-06_

## 背景

P0–P4 已有资产、静态扫描、Runtime Guard、Monitor、平台 API 和四个前端页面。当前文档中的 P5 仍只有 T01–T15 手工矩阵；一次性 pytest、单元测试和页面样例不能说明这些能力在同一条事件链上是否互通，也不能区分代码测试与真实 Agent 产品验收。

## 目标

提供一个默认离线、写入临时目录的 `agentsec poc run`，用一条合成会话串联以下证据：

1. **意图**：Hook 对普通读取放行，对敏感路径和未批准 MCP 工具拒绝；ASK/deny 输出符合 Claude Code 与 Codex adapter 契约。
2. **执行入口**：实际启动 Hook CLI 子进程，确认损坏 stdin 走 fail-closed，并检查返回协议。
3. **实际行为**：用合成 auditd 记录验证 Agent 子进程关联、敏感路径命中和 R005 读取后外联关联。
4. **Hook 强制边界与审计**：本地 Hook CLI 子进程证明 allow/deny；Monitor 只证明旁路观察；将事件送入隔离 FastAPI 应用和临时 SQLite，核对去重、会话统计与时间线。API 不被描述成执行网关。

POC 只使用仓库自带的安全/恶意 Skill fixture、虚构路径和保留测试网段地址；不访问真实凭证、外部服务或生产系统，不启用 auditd，不更改用户 Agent 配置，不上传事件。

## 范围与边界

- 自动验收本机可确定的静态扫描、策略纯函数、adapter 编码、Hook CLI、Monitor 解析/关联、Store/API 合同。
- 报告中明确标记这些是本地合成验收；不得据此宣称 Claude Code/Codex 信任门、实际 UI 浏览器交互、Linux auditd 安装或真实 Agent 工具执行已通过。
- JSON 报告使用 `schema_version=2`；每项检查都有 `product`、`product_version`、`adapter` 和 `version_status`。平台级检查将产品版本标为不适用；Claude Code/Codex adapter 检查将 `product_version=null`、`version_status=not_probed`，避免把离线协议合成测试写成真实安装版本验收。
- T01/T02/T03/T05/T06/T09/T11/T12/T13/T15 的真实设备/产品步骤继续作为人工验收项；T04/T07/T08/T10/T14 的本地策略路径可由安全 fixture 或 Hook 调用覆盖，但不触碰真实敏感文件。
- 发布者身份签名、Skill 安装准入签发/验签、MCP Tool 清单基线、强制网络/MCP 网关和动态沙箱是后续独立项目，不由 POC runner 模拟成已具备能力。

## 命令与输出

```bash
cd backend
python -m app.agent_security poc run --json
python -m app.agent_security poc run --output /tmp/agentsec-poc.json
```

默认仅把临时数据库、临时 `AGENTSEC_HOME` 和报告放在系统临时目录，完成后清理；`--output` 只保存去敏的检查结果。进程不得启用上传配置。失败检查返回非零退出码，并在同一 JSON 报告中保留步骤名、预期、实际值和错误摘要。

## 验收标准

- 恶意 Skill 命中 S01/S02 且有 block verdict；干净 Skill 不命中 block 规则。
- 敏感路径与未批准 MCP 调用被策略拒绝；允许路径不被误拦。
- Claude Code 与 Codex ASK/deny 输出包含各自 adapter 声明的事件名和决策字段；坏 stdin 不放行。
- Claude Code 坏 stdin 子进程必须以退出码 2 拒绝并输出阻断错误；Codex 坏 stdin 子进程必须以退出码 0 返回 `permissionDecision=deny`。
- Codex 声明的 PreToolUse matcher 必须命中 `mcp__filesystem__read_file`；移除 `mcp__.*` 后该 MCP 工具不再匹配，同时 `Bash` 仍匹配。此项仅验证能力矩阵声明，不代表真实 Codex 产品验收。
- 原始格式的合成 auditd 行经过 parser 并关联到指定 Session；敏感读取后窗口内外联产生一次 critical R005 告警，重复输入不重复告警。
- API 接受预期事件数、拒绝重复 event_id、为未知 Session 返回 404；Session 聚合数与时间线事件数匹配。
- 报告逐项标明 `passed`/`failed`、产品/版本/adapter 元数据，并声明 `synthetic=true`、`network_access=false`、`production_touched=false` 和 `enforcement_scope`（Hook only）。

## 后续顺序

1. 用真实 Claude Code/Codex 版本完成 Hook 协议与信任门验收；Linux 主机单独验证 auditd 规则和采集健康度。
2. 实现 Skill 安装准入：来源/发布者签名验证、静态分析、人工审核、本地审批签发、安装时重验内容摘要。发布者签名和本地审批签名是不同证据，不互相替代。
3. 设计并验证在路径上的执行控制面（优先明确 MCP/网络边界），并将旁路 Monitor 保留为独立观察证据。
4. 再评估动态沙箱和 WorkBuddy/Qcode 资产扫描扩展。
