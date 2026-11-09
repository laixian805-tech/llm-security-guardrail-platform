# Agent Security 测试机运行时实验计划

_P0 实验范围：Linux 测试机、auditd、execve/openat/connect、Agent session/PID 关联和 R005 · 2026-11-09_

## 目标

在可控测试机上证明四件事：

1. Agent 派生进程的 `execve`、敏感文件访问和公网连接能被采集。
2. 事件能沿 PID/PPID 链关联到 Agent session。
3. 敏感文件读取后在窗口内外联会产生一次 R005 correlation。
4. 非 Agent 进程不会被错误归因到 Agent session；无法关联时显示 orphan。

这是一套运行时可见性实验，不把 auditd 观察描述成操作系统阻断。

## 安装测试规则

测试机使用 UID/path-scoped 规则，避免影响其他用户：

```bash
sudo AGENTSEC_TEST_UID="$(id -u agentsec-lab)" \
  AGENTSEC_TEST_ROOT=/home/agentsec-lab/lab/agentsec-assets \
  bash scripts/agentsec-test-audit-install.sh
```

规则包含：

- 实验目录 `rwa` watch
- 测试 UID 的 `execve`
- 测试 UID 的 `connect`

开发机专用的宽范围规则也启用了 connect，但不应加载到共享生产主机：

```bash
sudo bash scripts/agentsec-audit-install.sh
```

## 实验场景

### E1：Agent 进程和普通子进程

从 Claude/Codex session 启动 `bash`、`python`、`node` 或 MCP server，确认：

```text
agent process -> child pid -> executable -> session_id
```

记录：`process_exec` 数量、session attribution rate、orphan 数量。

### E2：敏感文件读取

使用测试 fixture，不读取真实凭证：

```bash
mkdir -p /home/agentsec-lab/lab/agentsec-assets/secret-fixture
printf 'synthetic-secret\n' > /home/agentsec-lab/lab/agentsec-assets/secret-fixture/token.txt
```

让 Agent 或其子进程读取该 fixture，确认生成 `file_access`，路径经过脱敏/结构化处理。

### E3：敏感读取后公网连接

在同一 Agent session 中先读取 fixture，再连接测试域名或公网测试 IP：

```bash
curl -I --max-time 3 https://example.com/
```

在 300 秒 correlation window 内预期看到：

```text
file_access -> net_connect -> R005 candidate
```

R005 是高风险行为候选，不自动证明数据外泄。

### E4：非 Agent 进程和 orphan

- 直接从普通 shell 运行同样的 `curl`，确认不会被归因到 Agent session。
- 构造没有 SessionStart 注册但 comm 命中 Agent 的进程，确认生成 synthetic/orphan session。
- 报告 `orphan=true`，不能把它计入已确认 Agent session 的阻断证据。

## 单次采集和状态检查

```bash
AGENTSEC_AUDIT_LOG=/var/log/audit/audit.log \
AGENTSEC_HOST_ROLE=test \
python -m app.agent_security monitor once --no-upload --json

python -m app.agent_security monitor status --json
```

重点字段：

```text
records
events
inserted
backfilled_sessions
orphan_roots
audit_offset
heartbeat
audit_lag_bytes
heartbeat_overdue
```

## 验收指标

| 指标 | 计算方式 |
| --- | --- |
| Process attribution rate | 有 session_id 的 Agent descendant process_exec / Agent descendant process_exec 总数 |
| Orphan rate | orphan 事件 / runtime 事件总数 |
| R005 correlation count | 唯一 session + read path + connect window 的 R005 数 |
| Event completeness | audit serial 解析事件 / 规则命中事件 |
| p95 ingest latency | audit timestamp 到 SQLite event timestamp 的 p95 |
| Non-agent false attribution | 普通 shell 事件被错误绑定 Agent session 的数量，应为 0 |

## 结果记录格式

每次实验保存：

```json
{
  "host": "agentsec-test-01",
  "audit_rules_hash": "sha256...",
  "collector_version": "git-sha",
  "agent_product": "codex",
  "agent_version": "...",
  "scenarios": ["E1", "E2", "E3", "E4"],
  "process_events": 0,
  "file_events": 0,
  "network_events": 0,
  "attribution_rate": 0.0,
  "orphan_rate": 0.0,
  "r005_count": 0,
  "non_agent_false_attribution": 0
}
```

空值和未执行场景必须写成 `not_run`，不能填 0 冒充实验结果。

## 限制

- auditd 是旁路观察源，不提供 tool/process/network 阻断。
- connect 规则在共享主机上可能产生高量事件；测试规则优先使用 UID/path scope。
- 网络域名需要从连接 IP 或外部日志关联，auditd connect 本身不等于 HTTP URL。
- eBPF、Windows ETW、出口代理不属于本 P0 实验；后续能力见运行时覆盖设计文档。
