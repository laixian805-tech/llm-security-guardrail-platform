# Claude Code Hook 协议：2.1.152

状态：2026-11-11 在 `116.62.28.177` 的 `agentsec-lab` 用户中实测；使用 StepFun Step Plan，模型 `step-5-preview`。此验证不跨版本继承。

## 输入与字段

产品从 stdin 派发 JSON，Hook 经 stdout 返回结构化决策。配置位于测试用户的 `~/.claude/settings.json`。四类事件及脱敏实测 fixture：

| 事件 | fixture | 实测字段补充 |
| --- | --- | --- |
| SessionStart | `tests/fixtures/hooks/claude-code/2.1.152/SessionStart.json` | `source`；本次没有 permission_mode |
| PreToolUse | `tests/fixtures/hooks/claude-code/2.1.152/PreToolUse.json` | `tool_name`、`tool_input`、`tool_use_id`、`permission_mode`、`effort` |
| PostToolUse | `tests/fixtures/hooks/claude-code/2.1.152/PostToolUse.json` | 上述字段及 `tool_response`、`duration_ms` |
| SessionEnd | `tests/fixtures/hooks/claude-code/2.1.152/SessionEnd.json` | `reason`；本次值为 other |

共同有 session_id、cwd、transcript_path、hook_event_name。产品未提供通用事件时间戳，端侧以接收时间记 occurred_at。cwd、transcript_path、原始 tool_input/tool_response 留在本地处理，不随上报上传。

## 输出与产品回执

只有 PreToolUse 可输出：

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"ASGP endpoint rule"}}
```

- observe：exit 0、stdout 空。
- allow：输出 allow，真实安全命令成功创建证明文件。
- deny：输出 deny，真实工具被拒绝，证明文件不存在。
- ask：触发产品 can_use_tool 确认，接受后创建证明文件，拒绝时文件不存在。

非执行前事件一律 observe；本实现不用 exit 2。`Intent.decision` 只记发出的决策，不能单独作为实际阻断证明。

安装与回滚见 [接入 runbook](../runbooks/p1-hook-onboarding.md)，具体证据见 [实测报告](../acceptance/2026-11-11-p1.md)。

## ASGP 平台审批（后续首片）

除原生 ask 外，明确启用 approval_mode=control_plane 时可使用同 Codex 的绑定调用审批。测试机已验证批准前无 proof、批准后创建、拒绝/超时不创建；普通 observe 不访问审批服务。此通道和原生 ask 的证据分别保存，详见本轮 P2/P3 开始实施报告。
