# A.I.G 完整 Go/React 主平台是否纳入 ASGP

**结论：V1 不把 A.I.G 完整 Go/React 平台合并为 ASGP 主程序；继续直接复用其 Skill/MCP/Agent 扫描子项目。**

审阅的是本机完整检出的 `Tencent/AI-Infra-Guard`，revision `acddd07bfcab5c0c4a6eeefa487164ba34261c39`。结论限定在“是否把整个主平台作为 ASGP 底座”，并不否定 A.I.G 的扫描能力。

## 主平台源码提供什么

- Go 后端通过 Gin 提供平台 API、任务管理和 WebSocket Agent 通道；前端是 React/Vite。
- Agent worker 接收任务，再调用多个 Python 子项目，包括 Infra Scan、MCP Scan、Skill Scan、Agent Scan 和模型红队评估。
- 仓库既能作为完整 Docker 平台运行，也能把独立扫描器分别作为 CLI/PyPI 包使用。
- 主平台偏向 AI 红队和黑盒扫描工作流；Agent Scan 主要通过测试提示评估运行中的 Agent，不等同于 Claude Code/Codex 的 PreToolUse Hook，也不提供 Tool Call 到 OS 事件的因果归因主链。

## 是否将整套主平台并入 ASGP

| 选项 | 好处 | 代价/风险 | 结论 |
| --- | --- | --- | --- |
| 整体 fork A.I.G | 可直接得到其扫描控制台和任务工作流 | 把 Go/Gin/WebSocket/SQLite、Python worker、React 控制台、任务模型一并带入；会与 ASGP 的 Asset/Execution/Intent/Event/Incident 和新 API 重叠 | 不选作 ASGP 核心底座 |
| 只接入扫描子项目 | 保留其规则、扫描器和更新路径；ASGP 自己拥有 Finding、事件、归因和治理契约 | 需要维护适配器和上游版本映射 | V1 选择 |
| 独立部署 A.I.G 作对照 | 可并行比较红队/Skill/MCP 扫描结果 | 形成另一套控制台和存储，不应把两个平台的资产/风险口径混为一谈 | 可用于实验室对照，不作为 ASGP 主平台 |

阻止“整套直接合并”的两个具体边界：A.I.G README 明确说明默认没有认证，不建议部署到公网；其示例 Compose 给 Agent 容器授予 `SYS_ADMIN` 并设置 `seccomp:unconfined`。ASGP 当前端口会对公网开放，因此不能把这套默认部署边界直接继承过来。源码证据位于 A.I.G `README.md`、`docker-compose.yml`、`Dockerfile_Agent`、`cmd/agent/main.go` 和 `frontend/package.json`。

这不是说 A.I.G 不能用于企业环境；意思是其默认平台形态不符合 ASGP 当前的身份、权限和运行时归因边界。若以后考虑 fork，必须先做认证/RBAC、Worker 权限收敛、数据模型映射和 NOTICE 审查。

## 在 ASGP 中如何复用 A.I.G

1. 将 `aig-skill-scan`、`aig-mcp-scan`、`aig-agent-scan` 作为独立 Detector Adapter；安装时保留源 revision 和许可信息。
2. Adapter 保存原始输出，标准化成 ASGP Finding；记录上游 detector/version/rule ID，不能只复制一个总分。
3. A.I.G Skill/MCP LLM 扫描必须显示使用的 Provider Profile，并提示目标内容会发送到模型供应商。
4. `aig-agent-scan` 黑盒评估、A.I.G Skill/MCP 静态扫描和 ASGP OS 运行时监控属于不同能力/指标，不能互相替代或合并覆盖率。
5. 保留 A.I.G `LICENSE`、`NOTICE`，并持续在产品文档/About 中保留 NOTICE 要求的署名原文和仓库链接。

## 决策检查点

只有当 ASGP 明确把“现成红队控制台”定为产品核心，且愿意采用 A.I.G 的主平台任务模型时，才重新评估整体 fork。否则保持扫描器级复用，ASGP 自己负责 Agent Adapter、运行时采集、归因和治理闭环。
