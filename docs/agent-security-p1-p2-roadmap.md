# Agent Security P1/P2 路线图

_面向简历项目的可验证扩展路线 · 2026-11-09_

## P1：供应链补强与 MCP 执行来源

### P1.1 MCP execution origin

目标：回答“配置里声明的 MCP Server，实际会启动什么代码”。

第一期只追踪一级执行边界，不实现完整 npm/PyPI/Docker 供应链解析：

```text
MCP config
  -> command + args
  -> executable boundary
  -> parent/child process
  -> resolved package or unknown
```

支持的边界：

| command | 处理 |
| --- | --- |
| local executable | 记录 executable path，计算文件 hash |
| `python -m` | `unknown`，标记 runtime module resolution |
| `python script.py` | 记录脚本 path/hash |
| `npx/npm/pnpm/yarn/bun` | `dynamic`，标记可能远程下载或 mutable resolution |
| missing command | `unknown`，记录 `missing_command` |

### P1.2 运行时关联

将 execution origin 与测试机 PID 树关联：

```text
MCP instance_id
  -> server command
  -> spawned pid
  -> executable
  -> file/network events
```

必须保留：

- `execution_origin.command`
- `executable_path`
- `parent_pid`
- `pid`
- `resolved_hash`
- `resolution_status`
- `unknown_reason`

### P1.3 P1 验收数据

用三种 MCP fixture：

1. 本地 Python script：应得到 resolved executable/hash。
2. `python -m`：应得到 unknown/runtime resolution。
3. `npx -y`：应得到 dynamic，不得被报告为 verified。

简历中可以展示：

> 不仅扫描 MCP 配置，还将配置声明追踪到实际执行边界；对动态包管理器明确标记未知供应链风险。

## P2：可展望扩展

P2 暂不作为当前完成能力，只保留设计接口和实验方向。

### P2.1 Ed25519 release signature

目标：增加 release 完整性和发布者身份验证。

设计：

```text
asset release
  -> content_hash
  -> publisher public key
  -> Ed25519 signature
  -> trust root / revocation list
```

需要补充：密钥轮换、撤销、publisher namespace、签名格式和离线验证 fixture。

### P2.2 MCP lifecycle enforcement

事件拆分为：

```text
mcp_config_read
mcp_server_spawn
mcp_initialize
mcp_tool_registration
mcp_tool_invocation
mcp_server_termination
```

第一期只做 observe；只有确认产品或 MCP gateway 位于执行路径后，才升级为 ask/deny。

### P2.3 eBPF 对照采集

将 eBPF 作为独立 telemetry adapter，与 auditd 对照：

- execve 覆盖
- openat/file access 覆盖
- connect 覆盖
- PID/PPID 关联
- 丢失事件和性能开销

eBPF 采集本身不等于阻断。阻断需要 LSM、seccomp、cgroup 或其他位于执行路径的控制。

### P2.4 Windows ETW

Windows 只在有明确测试机后实施：

- process creation
- file access
- network connection
- Agent session association

Linux auditd/eBPF 的结果不能直接外推为 Windows 覆盖。

### P2.5 Network egress control

ThreatBook enrichment 和网络阻断严格分开：

```text
IOC reputation -> enrichment / evidence
egress proxy    -> in-path enforcement
```

只有存在代理、Firewall、namespace 或其他出口路径控制时，才统计 network deny success rate。

## 项目边界

当前项目优先交付：

```text
资产身份准确
Claude/Codex L3 Hook
Linux auditd runtime telemetry
PID/session/instance correlation
R005 sensitive-read-then-connect
ThreatBook 主动取证
MCP execution origin unknown/dynamic 标记
```

暂缓：全产品 L3、完整依赖闭包、企业 PKI、eBPF 阻断、Windows ETW、网络出口阻断。
