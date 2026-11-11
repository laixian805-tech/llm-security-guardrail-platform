> 后续修复：已新增并实测 ASGP 控制面调用审批，批准后返回 allow，拒绝/超时返回 deny。它以 mediated_approval_supported 单独声明，不把原生 ask 改为支持；证据见 [本轮报告](../acceptance/2026-11-11-p23-start.md)。下文原生 ask 的负面对照仍成立。

# Codex 原生 Hook 协议：0.166.0

状态：2026-11-11 在 `116.62.28.177` 的 `agentsec-lab` 用户中实测；保留现有 StepFun Responses profile，模型 `step-5-preview`。不再把 Codex 作为无法摄入的占位适配器。

## 配置与信任

当前安装版本原生支持 Hook。ASGP 在 `~/.codex/config.toml` 增量添加 SessionStart、PreToolUse、PostToolUse、SessionEnd 的 command Hook，并备份原始字节。产品的 `hooks/list` 接口返回各条命令的 currentHash；安装器仅为自己的四条命令写入 trusted_hash。未信任时 Hook 虽可被列出但不会派发，此状态不算接入成功。

本次 OpenAI 官方文档域名请求返回 HTTP 403，未据此编造文档结论；版本化接口 schema、运行安装版本的 hooks/list 结果和真实会话派发是本次接入证据。

## 真实输入

| 事件 | 相比 Claude 实测载荷的关键差异 |
| --- | --- |
| SessionStart | 包含 model、permission_mode 和 source |
| PreToolUse | 包含 model、turn_id；shell 在本次事件中的 tool_name 是 Bash，tool_input 为 command 对象 |
| PostToolUse | 包含 model、turn_id、tool_response，按 tool_use_id 与 Pre 关联 |
| SessionEnd | 有 reason；本次值为 other |

共同字段是 session_id、cwd、transcript_path、hook_event_name。实际 fixture 位于 `tests/fixtures/hooks/codex/0.166.0/`。端侧只上传调用 ID、工具名、参数结构/摘要哈希和短结果，不上传原始命令或 transcript。

## 决策能力的实测边界

| 决策 | 产品实际结果 | ASGP 行为 |
| --- | --- | --- |
| observe | 四类事件成功派发 | 默认模式，exit 0、stdout 空 |
| allow | 安全证明命令正常执行 | 可渲染；不宣称覆盖产品自身权限规则 |
| deny | 产品拒绝工具，证明文件未创建 | PreToolUse 声明 deny |
| ask | 产品忽略 ask，证明文件仍创建 | **不声明 confirm**；适配器拒绝渲染，控制面拒收 ask；需要确认的端侧规则改为 deny |

Codex 的 ask 不能因为和 Claude 的 JSON 字段相同就视为支持。改为 deny 是保守拒绝，不是人工审批实现；完整审批闭环属于后续治理工作。

安装与回滚见 [runbook](../runbooks/p1-hook-onboarding.md)，证据见 [实测报告](../acceptance/2026-11-11-p1.md)。
