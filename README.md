# LLM Security Guardrail Platform

这是一个本地 AI 安全实验平台，用来测试一套可审计的 Agent + RAG + Guardrails 架构。

当前这一版已经具备后端基础能力，包括：

- FastAPI 应用骨架
- Stub 与 Ollama 模型提供者抽象
- 统一的安全与评测数据结构
- 支持 `enforce`、`audit`、`off` 三种模式的分层护栏管线
- 带工具等级检查与参数策略检查的 MCP 风格工具网关
- 支持角色过滤、批量导出审计与可解释检索分数的持久化混合 RAG 基础能力
- 面向评测工具的 OpenAI 兼容 `/v1/chat/completions` 接口
- 内置探针、本地 JSON/CSV/HTML 报告输出的本地评测运行器
- 复用同一受护栏保护 OpenAI 兼容接口的 Garak 适配器
- 复用同一受护栏保护 OpenAI 兼容接口的 Promptfoo benchmark 适配器
- 覆盖 schema、guardrails、model provider、tool authorization 与 API 行为的单元测试

## 项目结构

```text
llm-security-guardrail-platform/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── config/
│   │   ├── guardrails/
│   │   ├── schemas/
│   │   └── tools/
│   ├── tests/
│   └── pyproject.toml
├── data/samples/
├── docs/
├── reports/examples/
├── scripts/
└── web/
```

## 存储布局

源码保留在仓库中，较大的运行时资产放在 WSL：

```text
/home/tlx/llmsec-assets/
├── chroma/
├── models/
├── ollama/
├── reports/
└── cache/
    ├── huggingface/
    ├── npm/
    └── pip/
```

在 WSL 中初始化这些目录：

```bash
cd /mnt/d/vscodefile/llm-security-guardrail-platform
bash scripts/init-assets.sh
```

## 后端启动

在 WSL 中执行：

```bash
cd /mnt/d/vscodefile/llm-security-guardrail-platform/backend
python3 -m venv .venv_server
source .venv_server/bin/activate
python -m pip install -e ".[dev]"
pytest -q
```

如果要在同一环境中启用 Garak：

```bash
python -m pip install -e ".[garak]"
```

如果要启用 Promptfoo benchmark，确保系统里可用 `promptfoo` CLI。
当前云端验证使用的是：

```bash
npm install -g promptfoo
```

启动 API：

```bash
uvicorn app.api.main:app --host 0.0.0.0 --port 8000 --reload
```

Windows 辅助脚本：

```text
scripts/start-backend-dev.cmd
```

健康检查：

```bash
curl http://localhost:8000/health
```

## 前端启动

在 Windows PowerShell 或 Command Prompt 中执行：

```bash
cd D:\vscodefile\llm-security-guardrail-platform\web
npm install
npm run dev
```

Windows 辅助脚本：

```text
scripts/start-frontend-dev.cmd
```

Vite 面板默认地址：

```text
http://localhost:5173
```

## 当前接口

- `GET /health`：检查服务状态与运行时路径配置。
- `POST /chat`：对配置好的模型提供者应用输入与输出护栏。
- `POST /tools/authorize`：执行工具等级与参数策略检查。
- `POST /rag/ingest`：把文本写入持久化混合 RAG 存储。
- `POST /rag/query`：按照角色可见性返回检索分块，并附带结构化 RAG 审计记录。
- `POST /eval/run`：运行本地安全探针并写出报告产物。
- `POST /eval/run` 搭配 `{"adapter":"garak"}`：对同一受护栏保护的 OpenAI 兼容接口运行 Garak，并把结果归一化成当前 API 返回结构。
- `POST /eval/run` 搭配 `{"adapter":"promptfoo"}`：对同一受护栏保护的 OpenAI 兼容接口运行 Promptfoo benchmark，并把结果归一化成当前 API 返回结构。
- `GET /reports/{run_id}`：返回指定评测运行的报告元数据。
- `POST /v1/chat/completions`：给 Garak、Promptfoo 等评测工具使用的 OpenAI 兼容对话接口。

## 模型提供者

后端默认使用 `LLMSEC_MODEL_PROVIDER=stub`，这样测试和前期 API 开发不需要先下载模型。

如果后续要切换到 Ollama：

```bash
cd /mnt/d/vscodefile/llm-security-guardrail-platform/backend
cp .env.example .env
# 编辑 .env 并设置：
# LLMSEC_MODEL_PROVIDER=ollama
# LLMSEC_OLLAMA_MODEL=qwen3:8b
```

然后启动 Ollama 并拉取模型：

```bash
ollama pull qwen3:8b
ollama serve
```

## 下一步实现目标

1. 在不破坏当前 API 契约的前提下，把 JSON 存储升级为 Chroma collections。
2. 增加可审计的 agent session 持久化。
3. 扩展 Promptfoo benchmark 用例集与断言强度。
4. 扩展 dashboard，补上更丰富的 Garak 和 Promptfoo 运行控制。

## 本地评测

先启动 API，然后运行一次本地评测：

```bash
curl -X POST http://localhost:8000/eval/run \
  -H "Content-Type: application/json" \
  -d '{"probes":["injection","role_override","encoding","jailbreak"],"guard_mode":"enforce"}'
```

报告默认写入：

```text
/home/tlx/llmsec-assets/reports/<run_id>/
├── results.json
├── results.csv
└── report.html
```

如果要对同一服务运行 Garak：

```bash
curl -X POST http://localhost:8000/eval/run \
  -H "Content-Type: application/json" \
  -d '{"adapter":"garak","probes":["injection","role_override","encoding","jailbreak"],"guard_mode":"enforce"}'
```

Garak 运行还会把原始 `.report.jsonl`、`.report.html`、配置文件以及 stdout/stderr 日志一起写到返回的报告目录里。

如果要运行 Promptfoo benchmark：

```bash
curl -X POST http://localhost:8000/eval/run \
  -H "Content-Type: application/json" \
  -d '{"adapter":"promptfoo","probes":["injection","role_override","encoding","jailbreak"],"guard_mode":"enforce"}'
```

Promptfoo 运行会写出：

```text
/home/tlx/llmsec-assets/reports/<run_id>/
├── results.json
├── promptfoo-results.json
├── promptfooconfig.yaml
├── promptfoo.stdout.log
└── promptfoo.stderr.log
```
