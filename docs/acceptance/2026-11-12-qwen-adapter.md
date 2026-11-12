# qwen-code 适配器与第三产品接入（2026-11-12）

目标：把产品覆盖从两个扩到三个。前提不是"能解析 payload"，而是**deny 真的能拦住执行**——没测过阻断能力就声明 deny，等于把平台的拦截能力建立在假设上。

## 实验方法

隔离 HOME（`/tmp/qwen-deny/home`），qwen-code 0.27.2 以 `--yolo` 连本地 mock OpenAI 服务（`127.0.0.1:8333`），mock 依次下发两次 `run_shell_command`：

1. `sh -c 'echo denied-path > /tmp/qwen-deny/work/deny.txt'` → hook 回 `permissionDecision: deny`
2. `sh -c 'echo allowed-path > /tmp/qwen-deny/work/allow.txt'` → hook 回 `permissionDecision: allow`

判据是**文件系统后果**，不是日志里的字样：deny 的命令不该产出文件，allow 的必须产出。

## 结果

| 检查 | 结果 |
| --- | --- |
| deny 命令的产物 `deny.txt` | **不存在**（被拦） |
| allow 命令的产物 `allow.txt` | **存在**（真的执行） |
| qwen 自己的提示 | `Warning: Tool "run_shell_command" was not run: asgp deny probe` |
| Hook 调用次数 | PreToolUse 2 次；PostToolUse **1** 次（被拦的那次没有 post） |

PostToolUse 只对放行的那次触发，这一条比提示文字更硬：被拦的工具调用在产品侧根本没有走到后置阶段。

## 声明了什么 / 没声明什么

| 项 | 结论 | 依据 |
| --- | --- | --- |
| SessionStart / PreToolUse / PostToolUse | 声明，字段映射按实测 | `tests/fixtures/hooks/qwen-code/0.27.2/*.json` |
| PreToolUse 的 observe + **deny** | 声明 | 上面的文件系统对照实验 |
| PreToolUse 的 **confirm/ask** | **不声明** | ask 未实测；渲染时直接 observe，不发产品可能忽略的指令 |
| SessionEnd | **不声明** | 未捕获到 payload，不猜字段 |
| `prompt_id` | 不外传 | 本机会话结构，列入 unsupported_fields |

字段纪律与 Claude Code 一致：payload 出现未声明字段直接报错，不静默忽略。qwen-code 多出的 `timestamp` 被用作事件时间（`occurred_at`），比端侧 stamp 更准；格式非法即明确失败。

## 覆盖现状

`GET /api/v1/products` 现在返回三个产品，能力矩阵逐条带 `evidence_ref`：

| 产品 | 版本 | 执行前能力 | 未声明 |
| --- | --- | --- | --- |
| claude-code | 2.1.152 | observe / confirm / deny | — |
| codex | 0.166.0 | observe / deny（原生 ask 被产品忽略，有负面对照） | confirm |
| qwen-code | 0.27.2 | observe / deny | confirm、SessionEnd |

## 未完成

- ~~qwen-code 尚未接进端侧实测链路~~ → 当日已完成，见 [qwen-code 端侧闭环](2026-11-12-qwen-endpoint.md)：真实 CLI + 真实模型 + 端侧 hook + 控制面纳管全部打通。声明版本由 0.27.2 改为设备实版本 0.26.8，两版抓包字段集一致、测试同时覆盖。
- Codex 的会话级加载探测命令未实测，产品路径 `verify` 对它仍返回 `unsupported_for_product`。
