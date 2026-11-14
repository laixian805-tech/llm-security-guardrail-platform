# 交接文档 · Agent 安全治理平台（ASGP）

> 写给接手的下一个对话/同事。本文自包含——不需要读之前的任何记录。

## 1. 这是什么

一个**面向 Agent CLI 的安全治理平台**：判定 Skill / MCP 包是否可信、把 Agent 的工具调用与系统事件对应起来、识别数据外发、给出处置决策。

不是通用 EDR，不是模型护栏。核心创新只有一条：**用 OS 层证据为 Agent 的行为建立归属，且在没有证据时留空**——市面上多数产品按"时间最近"硬连，那是猜。

代码在服务器 `43.139.77.64:/root/agent-security-fusion-platform`，仓库分支 `asgp`。

## 2. 五分钟上手

```bash
# 控制台（唯一对外入口，自签证书，浏览器会警告 → 高级 → 继续前往）
https://43.139.77.64/
# 账号 admin，密码在服务器 /root/.asgp/control-plane/service.env 的 FUSION_ADMIN_PASSWORD

# 跑全量测试（必须先跑通这个，再看别的）
ssh root@43.139.77.64
cd /root/agent-security-fusion-platform && ./scripts/test.sh
# 期望：487 passed（最新 P2 基线），且扫描器"未发现硬编码/重复真值问题"
```

## 3. 系统拓扑

| 角色 | 地址 | 跑什么 |
| --- | --- | --- |
| 主机 a | `43.139.77.64`（腾讯云，NAT，网卡 10.1.0.14） | 控制面 + nginx + 网页 |
| 主机 b | `116.62.28.177`（阿里云，测试用户 `agentsec-lab`） | 端侧采集器 + qwen-code |
| 本机 | Windows，用户 `tlx` | 只做评审与调度，不放业务文件 |

**端口**

| 端口 | 用途 |
| --- | --- |
| `127.0.0.1:8010` | 控制面本体（**只绑本地**，管理面不直接暴露） |
| `0.0.0.0:443` | HTTPS 入口（nginx，自签证书） |
| `0.0.0.0:8000` | **只做 301 跳转**到 443，不提供明文页面 |
| b `127.0.0.1:18082` | 端侧上报隧道，转发到 a `127.0.0.1:8010` |

隧道是 systemd 服务 `asgp-test-tunnel`，override 在 `/etc/systemd/system/asgp-test-tunnel.service.d/override.conf`。
nginx 配置在 `/etc/nginx/conf.d/asgp.conf`，归档副本 `deploy/nginx-asgp.conf`。

## 4. 已经建成什么（含实测数据）

| 能力 | 状态 | 关键指标 |
| --- | --- | --- |
| Skill / MCP 扫描 | 完成 | 5 个引擎接入（skillspector / snyk / mcp-scanner / aig ×3），同一输入 5 引擎 ≥3 一致率 2/5=40% |
| 准入状态机 | 完成 | 8 态：check→approve→stage→commit→verify / reject / rollback，非法跳转一律拒 |
| 风险与策略 | 完成 + 已验证 | 六组风险输入 **6/6** 命中预期规则；同一输入在 policy-v1 与 policy-eval-v2 下决策不同（confirm→block），复位后恢复 |
| 策略回滚 | 完成 | retired → active 需带原因，迁移记录标 rollback |
| 行为归因 | 完成 | 标注集 10 场景 13 事件：selected 精度 **0.8333** / 召回 **0.625**（`hook_id` 精度 0.6667，`process_tree` 精度 1.00，`false_strong_rate=0.125`）；any 精度 0.8889 / 召回 0.875 |
| 数据外发链 | 完成 | 30 条标注序列：**检出 15/15、误报 0/15**；关键负样本「读私钥 + git push github」不报 |
| 采集完整性 | 完成 | Audit 层 20 次操作零丢失；Hook 前置事件 25/25；后置 18/20（缺的 2 次由产品进程 OOM kill 导致） |
| 控制台 | 完成（聚焦改版） | 证据链与治理分组导航 + 发布者 Ed25519 验签 + EffectDiff 反事实差分面板 + 概览实时评测四卡（归因 156/22508） |
| 发布者验签（P0） | 完成（Schema v11） | `ed25519.py` 纯标准库 RFC 8032 验签 + `publishers` 表 + 吊销接口，拒收客户端自报布尔 |
| 副作用差分（核心突破） | 完成（Schema v12） | 来源谱系 `SourceKind` × 预期/OS 差分 `effect-diff-v1`；16 组 A/B 捕获 8/8（基线 0/8）、误报 0/8 |

## 5. 关键代码地图

```
backend/
  server.py                  HTTP 入口与全部路由（约 700 行，按 path 分支）
  domain/governance.py       RiskAssessment / PolicyRuleSet / Admission / Incident
  domain/asset.py            资产、实例、发布、Finding
  services/
    ingestion_service.py     摄入（鉴权、幂等、校验）
    attribution_service.py   归因：hook_id / process_tree / temporal_feature
    dataflow_service.py      数据外发链：source → hop → sink
    effect_diff_service.py   来源谱系 × 预期/OS 副作用差分（effect-diff-v1）
    evidence_rules.py        共享敏感路径 / 可信域名 / 路径归一规则
    ed25519.py               纯标准库 RFC 8032 Ed25519 服务端验签
    policy_service.py        策略版本：create / activate / rollback / evaluate
    managed_installer.py     准入落地、tree_hash、产品侧安装
    product_installer.py     写到产品 skills 目录
    asset_service.py         资产台账
  storage/schema.py          SQLite DDL + 迁移链（当前 SCHEMA_VERSION = 12）
endpoint/                    端侧（部署在 b 的 ~/.asgp/source）
  audit.py                   Linux auditd 采集（游标按 inode 分文件）
  redaction.py               参数脱敏 + resource_hints 路径提取
  hook.py                   产品 Hook 入口
web/                         控制台（无构建，index.html + app.js + styles.css）
scripts/lab/                 评测与扫描工具
  eval_attribution.py        归因标注集
  eval_dataflow.py           数据外发链标注集（30 条）
  scan_hardcoded.py          硬编码/重复真值扫描器
docs/acceptance/             验收记录（每份都带数字和边界）
deploy/                      nginx 配置与说明
```

## 6. 已知缺口（接手先看这个）

按重要性排序，前三个是"出事会难看"的：

| 优先级 | 缺口 | 具体表现 | 建议 |
| --- | --- | --- | --- |
| ~~P0（已修）~~ | `asset_releases.signature_verified` 服务端 Ed25519 验签 | 已合入（Schema v11）：`publishers` 公钥台账 + RFC 8032 服务端验签，客户端传 `signature_verified` 返回 400 | 保持不变；如需增强可接外部 PKI |
| ~~P1（已补）~~ | 纯 MCP 配置管道执行检测 | 已增 `mcp-config-guard` 本地静态守卫，覆盖独立 `mcp.json` 与内嵌 `mcpServers.args` 的 `curl \| sh`、未固定版本与明文凭据 | 后续可再叠加 LLM 语义分析 |
| ~~P1（已补）~~ | MCP 准入产品侧配置与会话枚举 | `endpoint/probe_product.py --asset-type mcp_server` 支持检测 `.qwen/settings.json`/`.claude.json`/`.codex/config.toml` 及 `<product> mcp list` | 需在实际准入流程中绑定端侧回传调用 |
| ~~P2（已补）~~ | 非环境变量 `SourceKind` + 推送 + `sendto`/PG 对等 + 外部轨迹基准 | 新增 `endpoint/lineage.py`（Host b 实测 `1.1–4.6ms`）、PG DDL 对等（29 表 295 列）、SSE/长轮询/异步入库、`sendto`/`sendmsg` + LOTS、`coverage_reports` 实库修复及 AgentDojo/InjecAgent 风格 N=40（Wilson 95% CI）评测（详见 [2026-11-14 P2 报告](acceptance/2026-11-14-p2-lineage-push-and-benchmarks.md)） | — |
| P2 | 数据流链只到路径级 | 证明"先读后发"，不证明字节流向；跨会话接力不覆盖 | 内容级需要端侧拦读写，量级不同，当前明确不做 |
| P2 | 归因标注集偏小 | 当前 10 场景 13 条事件，只能证明判据行为与故障注入边界，不能外推生产误报率 | 扩到 50+，加多 agent 并发 |
| P2 | Windows / macOS 采集未做 | 端侧只支持 Linux auditd | Windows 可做（Kernel-Process ETW）；macOS 受 entitlement 限制，建议只做接口不硬做 |

**已修但值得知道的**：采集器游标曾在日志轮转后越界，导致事件时间静默停在 7 小时前，上层所有时间窗关联全部错位。现在按 `(source, inode)` 分文件记游标，实测滞后从 48733 秒降到 53 秒。

## 7. 工程约定（必须遵守）

1. **修一处必须扫全场**。每修一个 bug、每发现一处硬编码，先问"这个错误模式还有多少处"。
   - 机器化保障：`scripts/lab/scan_hardcoded.py` 已挂进 `scripts/test.sh` 和 `tests/test_consistency.py`，零发现是门槛。
   - 已踩两次同类坑：测试写死 `schema_version == "8"`、`ADAPTER_VERSION` 定义后无人引用。
2. **一个语义只能有一个真值来源**。产品版本走 `PRODUCT_VERSIONS`，适配器版本走 `ADAPTER_VERSION`，schema 版本走 `SCHEMA_VERSION`。测试断言比常量，不写字面量。
3. **主机 a 的 codex / claude 禁止安装与测试**——那是用户的开发主力。产品侧验证一律放主机 b（`agentsec-lab`）。已加两道代码防护：项目根 `conftest.py` 的 `_never_start_product_cli`、`scripts/lab/product_load_probe.py` 的 `_refuse_developer_home()`。
4. **不写明文密码**到仓库、日志、配置样例。需要时从 `service.env` 读。
5. **拿不到的数据返回 `null`，不返回 `0`**——否则"没测"会被读成"没有"。
6. 验收记录必须带**数字**和**边界**。只写"已完成"的文档没有价值。

## 8. 踩过的坑（省你几个小时）

| 坑 | 现象 | 对策 |
| --- | --- | --- |
| 审计事件几乎不带 `execution_id` | 19940 条里只有 17 条有，按执行查永远为空 | 退回"同主机 + 时间窗"，并用 `sink_basis` 标注依据 |
| 时间窗上界用字符串比较 | `13:02:46` 把 `13:02:46.357` 排除，链永远为空 | 用时间戳计算 + 90 秒缓冲 |
| `PATH` 审计记录没有 `pid` | 按 pid 过滤审计日志得 0 条 | 用行号水位线统计 |
| outbox 因重试保留同 `record_id` 多条 | 计数虚高 | `distinct record_id` |
| observe 模式决策是 `not_applicable` 不是 `allow` | 按 allow 统计会得出"后置事件多于放行数"的假异常 | 按"是否被阻断"分类 |
| commit message 含中文引号 | heredoc 被 shell 解析中断，message 被截断 | `cat > /tmp/msg.txt <<'EOF'` + `git commit -F` |
| Git Bash 路径改写 | `scp` 把远端 `/tmp/` 改成 `C:/Users/.../Temp/` | 加 `MSYS_NO_PATHCONV=1` |
| 截图需要登录 | headless 无法交互 | 临时建 `web/_shot.html` 自动登录，**用完必须删**（内含明文密码） |

## 9. 常用命令

```bash
# 全量测试（含扫描器）
ssh root@43.139.77.64 'cd /root/agent-security-fusion-platform && ./scripts/test.sh'

# 单独跑标注集
ssh root@43.139.77.64 'cd /root/agent-security-fusion-platform && \
  .venvs/control-plane/bin/python scripts/lab/eval_dataflow.py'

# 重启控制面
ssh root@43.139.77.64 'systemctl restart asgp-control-plane && sleep 4 && systemctl is-active asgp-control-plane'

# 端侧采集一次并上报
ssh root@116.62.28.177 'su -s /bin/bash agentsec-lab -c "cd /home/agentsec-lab/.asgp/source && \
  sg adm -c \"ASGP_ENDPOINT_CONFIG=/home/agentsec-lab/.asgp/endpoint/config.json \
  timeout 90 /usr/bin/python3 -m endpoint.audit --once\" && \
  ASGP_ENDPOINT_CONFIG=/home/agentsec-lab/.asgp/endpoint/config.json \
  timeout 120 /usr/bin/python3 -m endpoint.flush"'

# 契约漂移检查（改过 domain 模型后必跑）
ssh root@43.139.77.64 'cd /root/agent-security-fusion-platform && \
  .venvs/control-plane/bin/python scripts/export-schemas.py --check'
```

## 10. 接手建议

先跑 `./scripts/test.sh` 确认 **487 passed** 且硬编码扫描器 0 问题，再打开控制台 `https://43.139.77.64/` 看概览评测对比卡片是否正常。

若继续在主机 `b`（`116.62.28.177`）跑真机 `qwen-code`：需先在阿里云控制台重启主机 `b`（该机在 1.7 GiB RAM + 临时 `/swapfile` 跑完整 Node `qwen` 时出现 SSH banner 超时），重启后删除 `/swapfile` 再通过轻量场景或单步采集执行。
