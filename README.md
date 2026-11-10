# ASGP · Agent Security Governance Platform

ASGP 是独立的 Agent 安全治理平台，目标是把多产品 Agent 接入、检测器复用、运行时行为归因和治理处置统一到一个平台中。它不复用旧平台的数据库、API 或前端。

## 当前阶段

当前运行版本是**扫描引擎集成原型**：

- 已接入 SkillSpector、Snyk Agent Scan、Cisco MCP Scanner，以及 A.I.G 的独立扫描 CLI。
- 接受 SARIF 2.1.0 和扫描器 JSON 报告，并保留引擎、规则、证据位置和风险分。
- 使用 SQLite 保存扫描记录；扫描目标限制在 `workspace/`。
- 页面、API、扫描适配器和结果存储是 ASGP 自己的控制面骨架。

Execution/Intent/Event 采集、进程/文件/网络关联、策略拦截、准入事务和 Incident 闭环属于目标架构，尚未实现。整体分层见 [ARCHITECTURE.md](ARCHITECTURE.md)，数据结构见 [DATA_MODEL.md](DATA_MODEL.md)，接口见 [API_CONTRACT.md](API_CONTRACT.md)，实施次序见 [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md)。A.I.G 主平台是否纳入 ASGP 的评审见 [docs/aig-platform-review.zh-CN.md](docs/aig-platform-review.zh-CN.md)。

旧平台模块如何映射到 ASGP、哪些概念保留而不搬运代码，见[旧平台审计与迁移映射](docs/legacy-platform-review.zh-CN.md)。

## 启动

需要 Python 3.12 或更高版本。平台服务使用 Python 标准库；各扫描器安装在独立虚拟环境中，避免依赖冲突。

```bash
./scripts/setup-engines.sh
cp .env.example .env
# 在 .env 中填写密钥后启动
FUSION_BIND=0.0.0.0 PORT=8000 ./scripts/run-local.sh
```

当前演示地址为 `http://43.139.77.64:8000`。扫描目标放入 `workspace/`，页面填写其相对路径。引擎源码路径由 `FUSION_UPSTREAM_ROOT` 和 `FUSION_AIG_SOURCE_ROOT` 指定。

## 模型 API

- StepFun 为 ASGP 主用供应商，模型服务配置由 `ASGP_MODEL_PROVIDER=stepfun` 选择。
- 讯飞星火作为候选，设置 `ASGP_MODEL_PROVIDER=xunfei` 前需验证对应 Chat Completions 端点和模型。
- 平台读取 `~/.codex/config.toml` 中 StepFun/讯飞的供应商 ID、接口地址、`wire_api` 和各自的 Authorization Bearer 头。`STEPFUN_API_KEY`、`XUNFEI_API_PASSWORD` 可分别覆盖 Codex 配置；配置头只在内存中读取，不回显或持久化。
- Codex 当前 provider profile 使用 Responses；A.I.G 扫描 CLI 使用 Chat Completions。平台为两种协议保留独立配置，不能把 Responses 地址直接交给 Chat Completions 客户端。
- 密钥只从本机 `.env`、Codex provider 配置头或进程环境读取，不保存到 SQLite、日志或命令行参数。Snyk 另需 `SNYK_TOKEN`。

### Provider Probe

`POST /api/providers/{id}/probe` 分别探测该供应商的两条传输 profile（Codex 的 Responses、扫描器的 Chat Completions），返回状态、延迟、协议、HTTP 状态、端点回显的模型和被接受的结构化/工具调用能力，不回传密钥。端点不可达、超时、凭据被拒、协议形状不符、模型不符、能力被拒都记为失败并落库。

- Probe 失败的 provider 不进入默认路由，主用和候选一样；候选还要求已经通过 Probe 才能被选中。
- 拒绝路由时不静默回落到主用，否则配置错误会被藏起来。
- Codex profile 的模型必须用 `STEPFUN_CODEX_MODEL` / `XUNFEI_CODEX_MODEL` 显式指定：Codex 顶层的 `model` 属于当前 `model_provider`，换一家供应商未必存在，拿它探测只会得到假的 404。
- 通过 Responses profile 不代表 Chat Completions profile 可用——两者 endpoint、协议和工具 schema 都不同，必须分别探测。

## 引擎边界

- SkillSpector 运行静态扫描并关闭 LLM 分析；OSV 查询可能访问网络。
- A.I.G Skill/MCP 扫描会把目标内容发送给当前选定的模型服务，必须由用户明确启动。
- Snyk Agent Scan 仅允许扫描 Skill 目录或 `SKILL.md`；需要 `SNYK_TOKEN`，不会扫描可启动 MCP 命令的配置。
- Cisco MCP Scanner 只运行静态工具清单模式，不连接远程服务或启动 stdio MCP 进程。
- A.I.G Agent Scan CLI 已安装，但 ASGP 暂不从页面启动动态 Agent 测试。
- ToolHive 是 MCP 运行时网关，不是扫描器；目前列为后续数据面候选。
- LLM Guard 上游已归档，不作为主动执行的防护依赖。

## 安全与许可

当前实例绑定 `0.0.0.0:8000`，尚未实现登录鉴权。此配置仅用于本轮查看原型；不要在 `workspace/` 放入敏感数据。正式公网部署前必须增加身份认证、权限管理和运行时隔离。

上游来源与许可见 [UPSTREAMS.md](UPSTREAMS.md) 和 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。若发行包直接包含 A.I.G 源码，须保留其 `LICENSE`、`NOTICE` 并满足署名要求。
