# 产品 Hook 协议边界与验证证据

状态：已采纳；2026-11-11 由测试机实测更新。

ASGP 使用产品原生 Hook 获取 Execution/Intent 上下文。MCP 只能观察经由自己的工具调用，不能替代任意产品工具的执行前观测点。端侧 Hook 每次只做本地解析、参数省略和 SQLite 持久写入，独立 reporter 异步上报，执行路径不等待远端模型或控制面。

## 决策

1. **能力按产品、版本、事件声明。** 测试机实测 Claude Code `2.1.152` 和 Codex `0.166.0` 均派发 SessionStart/PreToolUse/PostToolUse/SessionEnd。版本化 fixture 保存经过路径、会话 ID 脱敏的真实字段形状；验收报告保存产品执行结果。其他版本不自动继承 verified。
2. **只在执行前表达决策。** 非 PreToolUse 永远返回 observe。observe 模式 exit 0、stdout 空；决策统一使用 stdout 的 `hookSpecificOutput.permissionDecision`，不用 exit 2。决策记录不是 EnforcementEvidence。
3. **Codex confirm 明确不支持。** 测试证明 `0.166.0` 会忽略 `permissionDecision=ask` 并执行工具；该版本只声明 observe/deny。控制面拒绝它上报 ask 决策，适配器拒绝渲染 ask，端侧需要确认的规则改为 deny 并给出 `confirmation unsupported` 原因。不能用格式能序列化来推导产品执行了该语义。
4. **Claude confirm 有真实回执。** `2.1.152` 的 ask 触发 can_use_tool 确认；测试分别接受和拒绝，证明文件结果与选择一致。它的 PreToolUse 可声明 observe/confirm/deny。
5. **Codex 信任配置属于接入流程。** 安装器向运行中的产品接口 `hooks/list` 取得新增四条 Hook 的 currentHash，只信任本安装器生成的命令，不信任其他已有 Hook。只写配置但未登记信任不足以宣称已接入。
6. **未知字段和版本变化保守处理。** 未知协议字段解析失败，端侧 observe 并记录不含原始输入的错误 ID。安装器记录产品可执行文件的 stat 指纹；文件变化后事件以 `unverified-changed` 上报，并关闭端侧决策，等待重新核对。
7. **用户授权限定安装位置。** 真实安装与受控实验只在 `116.62.28.177` 的专用测试账户执行；开发控制面不安装产品 Hook。安装器先备份，重复安装幂等；卸载时先检查文件是否被其他人修改，再精确恢复原始字节，冲突时保留备份并拒绝覆盖。
8. **身份和数据边界不变。** 设备凭据不授予控制台权限；服务端用设备绑定覆盖 host/device。原始 prompt、命令/参数值、工具输出和环境变量不上传；只保存工具名、调用 ID、参数结构/哈希和短状态。

## 后果与证据

- 当前控制面可以摄入两个产品；Codex 已从原来的“协议未知，拒绝摄入”改为有实测依据的接入。
- 默认模式仍为 observe。确认/拒绝的规则验证只在测试用户的无害 proof 文件目录内进行，不代表已完成 P3 Policy/Admission/Incident。
- 端侧无需守护进程接收工具调用，后台 reporter 由 systemd 管理；测试传输使用 SSH 加密隧道，非公网生产接入。
- 证据见 [P1 实测报告](../acceptance/2026-11-11-p1.md)、`tests/fixtures/hooks/` 和 `tests/test_hook_fixtures.py`。
