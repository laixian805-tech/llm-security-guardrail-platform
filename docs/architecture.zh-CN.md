# 当前 ASGP 实现架构

2026-11-11 更新；目标设计见根目录 ARCHITECTURE.md，实测证据见 [P1 报告](acceptance/2026-11-11-p1.md)。

实际控制面为 Python ThreadingHTTPServer + Pydantic + SQLite 原生 SQL + 静态 HTML/CSS/JavaScript；没有迁移到 FastAPI、SQLAlchemy、React 或 PostgreSQL。

- 扫描：控制台认证/RBAC → `ScanService` → `DetectorCatalog` / Detector Adapter → 独立 CLI → 标准 Finding/RawReport/DetectorRun。
- 执行：测试机原生产品 Hook → 本地协议映射/参数值省略 → SQLite outbox → 独立 reporter → SSH 加密隧道 → 设备令牌认证/host 覆盖 → Execution/Intent/RuntimeEvent 仓储。
- 查询：控制台会话 → 执行列表/稳定游标时间线 → 只读 UI；页面明确展示未实现的 Attribution/Finding/Policy 部分。

设备凭据与控制台会话分离，状态数据库 schema v5。关键实现分别位于 `backend/server.py`、`backend/api/v1.py`、`backend/services/`、`backend/adapters/`、`backend/storage/` 与 `endpoint/`。

产品验证只覆盖 Claude Code 2.1.152、Codex 0.166.0；两者都已接入，Codex ask 不支持。默认 observe，决策记录不是实际阻断证据。

Linux Audit、事件归因、资产注册中心、Policy/Admission/Incident、微服务及 OS 沙箱均不能视为当前已交付。venv 是依赖隔离，不是执行沙箱。部署服务及备份/卸载流程见 [runbook](runbooks/p1-hook-onboarding.md)。
