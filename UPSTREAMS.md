# 上游引擎与集成边界

平台把扫描器当作独立引擎运行。每个引擎保留自己的发现项与来源；平台只统一存储和展示，不把不同引擎的判断改写成同一套风险语义。

| 引擎 | 上游项目 | 许可 | 在平台中的作用 | 执行边界 |
| --- | --- | --- | --- | --- |
| SkillSpector | [NVIDIA/SkillSpector](https://github.com/NVIDIA/SkillSpector) | Apache-2.0 | Skill 主扫描器；支持 CLI 和 SARIF 导入 | 静态扫描；关闭 LLM；OSV 查询可能访问网络 |
| A.I.G Skill Scan | [Tencent/AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard) | Apache-2.0，另有仓库 NOTICE | LLM 辅助 Skill 审计 | 用户明确启动；扫描内容会发送到配置的模型服务 |
| A.I.G MCP Scan | [Tencent/AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard) | Apache-2.0，另有仓库 NOTICE | MCP 服务源码审计 | 用户明确启动；扫描内容会发送到配置的模型服务 |
| Snyk Agent Scan | [snyk/agent-scan](https://github.com/snyk/agent-scan) | Apache-2.0 | Agent/Skill 发现和风险扫描 | 当前仅运行 Skill 路径；需要 `SNYK_TOKEN`；不扫描会启动服务器的 MCP 配置 |
| Cisco MCP Scanner | [cisco-ai-defense/mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner) | Apache-2.0 | MCP 工具定义静态分析 | 只接受静态工具清单；不连接远程服务或启动 stdio 服务 |
| ToolHive | [stacklok/toolhive](https://github.com/stacklok/toolhive) | Apache-2.0 | 后续 MCP 注册与运行时网关 | 独立运行时组件，不产出静态扫描发现项 |
| LLM Guard | [protectai/llm-guard](https://github.com/protectai/llm-guard) | MIT | 输入/输出扫描能力参考 | 上游已归档，目前不作为主动执行的防护依赖 |

本地安装/审阅版本：

| 仓库 | 修订版本 | 当前状态 |
| --- | --- | --- |
| NVIDIA/SkillSpector | `ccbad7fb852de601c4e5b7c9193cd02d0fa3571f` | v2.12.0，安装于 `.venvs/skillspector` |
| snyk/agent-scan | `59def8c624f9d7bef4d49992a4da5e68f83f4e75` | v0.6.11，安装于 `.venvs/snyk-agent-scan` |
| cisco-ai-defense/mcp-scanner | `9ff8fc84b792aae315a838cf4e37b40ef46a0293` | v4.8.7，安装于 `.venvs/mcp-scanner` |
| Tencent/AI-Infra-Guard | `acddd07bfcab5c0c4a6eeefa487164ba34261c39` | 完整源码已审阅；Skill/MCP/Agent 三个 CLI 从本地源码独立安装 |
| protectai/llm-guard | `168c1034ffdb33837e7ae6fd6a16b80567c1be03` | 已审阅；上游归档，未安装 |

## 集成说明

- 上游提供 SARIF 2.1.0 时，平台保留原始引擎名、规则 ID、严重级别、位置和消息。
- Snyk Agent Scan 声明其 CLI 输出格式仍可能变化，因此它的原始 JSON 仅由适配器读取，不作为平台 API 契约。
- Cisco MCP Scanner 与 Agent Scan 的部分运行模式会连接远端 MCP 服务或启动本地 MCP 命令；当前工作台只开放静态扫描模式。
- A.I.G 上游默认 Docker 部署没有认证。本平台当前可按 `FUSION_BIND` 监听公网接口，接口本身尚无登录认证。

## 源码位置

NVIDIA/Snyk/Cisco 源码审阅副本位于 `/root/opensrc/agent-security-landscape/`；A.I.G 完整源码位于 `/root/opensrc/AI-Infra-Guard/`。它们未整体复制进 ASGP 工作树。扫描引擎通过独立虚拟环境中的 CLI 调用，或通过 SARIF/JSON 导入，从而避免依赖冲突。
