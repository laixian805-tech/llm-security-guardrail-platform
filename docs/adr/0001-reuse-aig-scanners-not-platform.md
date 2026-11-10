# 复用 A.I.G 扫描器，不复用完整主平台

状态：已采纳。

ASGP 不把 A.I.G 完整 Go/React Web 平台合并为控制面。A.I.G 已有红队控制台和扫描任务编排，但 ASGP 需要自己的 Asset/Execution/Intent/Event/Incident 领域模型以及长期运行时归因；整套合并会同时带入另一套 API、任务模型、存储和前端。A.I.G 默认部署还缺少认证，示例 Agent 容器带 `SYS_ADMIN` 和 `seccomp:unconfined`。ASGP 通过版本化 Detector Adapter 复用其 Skill/MCP/Agent 独立扫描器，并保留 `LICENSE` 与 `NOTICE` 署名。只有 ASGP 改变产品边界并完成安全加固后，才重新评估整个平台 fork。
