# ASGP endpoint

Python 3.10+，仅标准库。测试机真实接入 Claude Code 2.1.152 与 Codex 0.166.0；端侧依赖与控制面分开部署，不导入 backend。

- `hook.py`：产品 stdin → 版本化协议映射 → 参数值省略 → 一次 SQLite 事务入队。默认 observe，不等待网络。
- `redaction.py`：本地脱敏后计算哈希；上传结构摘要，不上传原始命令、prompt、环境变量或完整工具结果。
- `outbox.py`：WAL + synchronous FULL，默认 10,000 条、32 MiB 主库容量门槛；超限记录错误，不无限增长。
- `flush.py`：单实例文件锁、崩溃恢复、稳定 ID 重放、指数退避；4xx（408/429 除外）进 dead，5xx/网络错误重试，默认最多 20 次；sent 保留 7 天。
- `install.py`：两产品分别备份、幂等安装、精确卸载与并发修改检测；Codex 只信任自己的四条 Hook。

配置使用 JSON，避免测试机 Python 3.10 缺少 tomllib。配置文件含设备令牌，权限 0600；状态目录 0700。HTTPS 是远程默认要求，HTTP 仅允许 localhost 的加密 SSH 隧道入口。reporter 不跟随重定向，避免把设备令牌发送给其他地址。

```bash
python3 -m endpoint.install --config /private/asgp/config.json --print
python3 -m endpoint.install --config /private/asgp/config.json
ASGP_ENDPOINT_CONFIG=/private/asgp/config.json python3 -m endpoint.flush --once
python3 -m endpoint.install --config /private/asgp/config.json --uninstall
```

安装前 config.json 需包含 server_base_url、device_token、state_dir、product_versions 和 fail_mode。产品可执行文件须位于 PATH；安装器保存 stat 指纹，产品文件变化时以 unverified-changed 上报并降为 observe。

`fail_mode=deny` 只用于明确验证的产品版本；deny_patterns/ask_patterns 是端点本地简单测试规则，不是 P3 策略引擎。Codex 0.166.0 忽略 ask，所以需确认的规则在端侧直接拒绝并注明原因；Claude 的 ask 已实测支持。默认部署保留 observe。

已知限制：Hook 不可用/解析失败/队列满/超时均可能漏掉观测，不能宣称 fail-closed 安全边界；脚本外的工具执行也不受 Hook 保护。sessions 元数据、已删除页和 WAL 的完整磁盘配额/压实治理仍待补充；容量门槛不等于文件系统硬配额。状态在用户可写目录中，不提供对该用户本身的防篡改保证。正式多租户生产部署、mTLS、OS 采集、归因和策略闭环属于后续范围。

测试机实测一次 Hook 启动及 SQLite 持久写入中位数约 79 ms，10 次样本最大约 97 ms；这是小样本结果，不是性能 SLA。
