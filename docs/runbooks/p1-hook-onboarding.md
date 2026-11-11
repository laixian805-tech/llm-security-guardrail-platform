# P1 两产品测试机接入与回滚

当前拓扑：开发机运行 ASGP 控制面；`116.62.28.177` 的非 root `agentsec-lab` 运行 Codex、Claude 和 endpoint。root SSH 只用于部署管理，模型任务不用 root 执行。

## 当前部署

| 位置 | 路径/服务 |
| --- | --- |
| 开发机控制面 | `asgp-control-plane.service`，127.0.0.1:8000 |
| 开发机加密隧道 | `asgp-test-tunnel.service`，反向映射测试机 127.0.0.1:18082 → 控制面 |
| 测试端源码 | `/home/agentsec-lab/.asgp/source/endpoint/` |
| 测试端私有配置/状态 | `/home/agentsec-lab/.asgp/endpoint/`，config.json 为 0600 |
| 测试端 reporter | `asgp-endpoint-flush.service`，User=agentsec-lab，MemoryMax=96M |
| 开发端管理员口令 | `/root/.asgp/control-plane/admin-password`，0600；不要写入工单/日志/argv |
| 开发端迁移前备份 | `/root/.asgp/control-plane/fusion-before-p1.db` |

无需保存 SSH 密码到仓库或服务。隧道使用独立密钥，测试用户 authorized_keys 限制命令及 permitlisten=127.0.0.1:18082；端点新端口只监听 loopback。服务均已设置开机启动和失败重启。

浏览器需要从有权限的终端经 SSH 转发访问控制面 127.0.0.1:8000；登录 admin 后刷新“运行时间线”。当前未新增公网入口。

## 新设备/令牌管理

1. 管理员登录 `POST /api/session`，通过 `POST /api/devices` 登记设备；令牌只在创建时返回一次，写进端点私有配置。
2. `PATCH /api/devices/{id}` 写入 host_id；设备后续不能改绑其他主机，应重新登记。未绑定的设备上报返回 409 host_unbound。
3. 端侧记录 ID 随重试稳定，后端覆盖客户端 host/device，跨设备引用 Execution 返回 409。
4. 轮换：`POST /api/devices/{id}/rotate-token` 返回新 token，旧 token 即刻失效。停止 reporter，更新私有配置，再启动；轮换期间先暂停上报，避免旧 token 的 401 使记录进入 dead。
5. 吊销：`PATCH /api/devices/{id}` 设置 status=revoked。后续写入 403，端侧进入 dead，不无限重试。
6. dead 记录不会自动重放；先按 last_error 确认原因、修复身份/依赖后，由管理员明确选取记录恢复 pending。不要将来自未知设备的数据改成当前设备身份强行补传。

## 安装和卸载

在测试用户的 PATH 中加入其现有 Node/npm bin，在 endpoint 源码根执行：

```bash
python3 -m endpoint.install --config /home/agentsec-lab/.asgp/endpoint/config.json --print
python3 -m endpoint.install --config /home/agentsec-lab/.asgp/endpoint/config.json
```

安装器只追加自己的 Hook，保留 StepFun 供应商和其他设置。Codex 的 Hook 信任必须来自产品 hooks/list 的 currentHash，不能靠猜哈希或信任其他人的 Hook。安装器重复执行返回 already_installed。

卸载：先停止 reporter，再执行相同命令加 `--uninstall`。安装器校验 installed_sha256 后恢复备份；若文件期间被修改则拒绝覆盖，保留原始备份供人工合并。不要直接覆盖整个用户配置。

开发机不安装 Hook。产品升级后重新核对版本与 fixture，不直接沿用已验证能力。**Codex 0.166.0 不支持 Hook ask，禁止把它配置成可以放行的“等待确认”。**

## 排查

- 无事件：检查 Hook 是否安装、产品版本和 Codex 的 trustStatus，再看错误 event_id；不要输出原始 stdin/prompt。
- pending 增加：先看隧道、控制面和 next_attempt；网络错误按退避恢复，不应手工生成新事件 ID。
- dead：按 http_401/http_403/http_409 等原因处理。错误正文不存入端侧日志，防止服务端回显敏感数据。
- 看队列仅查询 state/count、record_id、last_error；不要把 config.json 或完整 payload 打进日志。
- `ASGP_V1_ENABLED=0` 可使版本化 API 返回 503，既有控制台扫描仍可用。

## 数据与代码回滚

停止 Hook/reporter 与控制面后，SQLite 回滚优先恢复部署前的完整备份（仅用于明确接受丢弃本次部署新增数据的情形）。只回退代码不会删除 v5 的表或新增列。迁移为增量建表和加列，旧扫描代码可忽略新表，但必须验证目标旧版本后再恢复服务。备份包含身份与报告，按私有数据保护。

正常卸载保留 outbox，便于重新安装续传；不要将“删除整个状态目录”作为默认卸载步骤。测试隧道停用后可停掉 asgp-test-tunnel，并移除专用公钥条目及本机专用私钥，保留其他用户 SSH 配置。

## 复跑

```bash
./scripts/test.sh -q -rs
./scripts/e2e-hook-timeline.sh
node --check web/app.js
```

第二条使用版本化真实 fixture 调用实际 endpoint CLI 和临时 HTTP 控制面，验证两产品时间线、重放去重和吊销队列；它属于 fixture 联调，不能代替产品实测。实测证据另见 [P1 报告](../acceptance/2026-11-11-p1.md)。

## P1 审批修复与 P2 采集新增部署

- 测试机新服务 asgp-audit-collector：agentsec-lab + SupplementaryGroups=adm，CPUQuota=10%，MemoryMax=96M，只读 Audit、状态写目录单独开放。
- 新文件规则仅 `/home/agentsec-lab/lab/asgp-p23` 的 asgp_p2_files；exec/connect 复用旧项目已有 UID 1000 规则，不清空旧规则或停止旧服务。
- config 增加 approval_mode=control_plane、approval_timeout_seconds=15、runtime_anchors=true、audit_log、audit_uid、audit_keys。当前默认 fail_mode=observe；命中需确认规则才启用同步审批。PreToolUse timeout=25，其他 Hook=3。
- 本轮部署前私有备份为开发机 fusion-before-p23.db、测试机 config-before-p23.json。迁移为 schema v6，新增调用审批/归因/风险/策略/准入/Incident/历史表；早期试运行归因表会补源记录级联关系。
- 审批可在“调用审批”页面处理，或 govern 权限调用 POST /api/v1/approvals/{id}，body 含 decision（approved/denied）和本请求 params_sha256。禁止脚本自动批准真实用户请求；自动测试批准只针对明确的合成/无害测试调用。
- 关闭本轮 collector 时先停止服务，只卸载 asgp_p2_files watch 和 98-asgp-p2.rules，不执行 auditctl -D。旧规则由原服务维护。Hook 的回退仍用精确卸载/重装，不覆盖他人配置。
- Audit 事件无 execution_id 是有效结果；先执行 correlate 建立证据候选，不直接给事件改上 execution_id。selected 仍是当前证据选择，不是已证因果。
- 新状态机只提供已明确交付的动作；Admission 的 stage/commit/verify 目前 409 installer_required，不在此 runbook 宣称安装已经完成。
