# ASGP 专家评审与技术面试拷打报告（只读实证版）

> **评审日期**：2026-11-14  
> **评审基线**：Host a（`43.139.77.64:/root/agent-security-fusion-platform`，提交 `02821dd`）源码、`data/fusion.db`（只读实库查询与回放）、`scripts/lab/eval_*.py`、`docs/acceptance/*.json` 与本地文档。  
> **评审双视角**：  
> 1. **AI/Agent 安全技术面试官 & 红队架构审计（`interview-griller`）** —— 审视是否超越“玩具（Toy）”、真实防御边界、全链路绕过面与面试/答辩深水区拷打；  
> 2. **顶会系统安全审稿人 & 实验方法学审计（`paper-exp-reviewer`）** —— 审视威胁模型与 TCB、合成集 vs 实库偏差、缺失消融与基线、`2C2G` 系统开销缺口、实验补全路线。

---

## 一、联合定性总评：哪里超越了“玩具（Toy）”，哪里仍属原型/启发式

ASGP 在架构哲学上具有明确且稀缺的工程/学术直觉：**拒绝将静态风险分与运行时遥测折叠为单一黑盒分数、严格区分“资产已安装（Installed）”与“产品真实加载（Loaded）”、坚持“无确凿 OS 证据时不硬连（Abstention over Guessing）”，以及围绕 `non-self-asserting evidence` 设计控制面门禁**。

但按大型企业级防御体系与顶会系统安全审稿标准，当前阶段属于**“核心治理思想成立、服务端门禁扎实，但威胁模型尚未闭合、端侧防御与归因在真实宿主机并发流量下存在结构性盲区/误报、且现有评估仍高度依赖小规模手写合成集”的早期系统原型**。若未经补强直接按“高精度/零误报”口径对外答辩或投稿，会在真实样本回放与红队对抗追问下被直接击穿。

### 1.1 真正超越 Toy 的工程与安全防线（核心护城河）

| 能力模块 | 源码位置 | 超越 Toy 的实质工程设计 |
| --- | --- | --- |
| **抗“客户端自证”发布者验签** | `backend/services/asset_service.py:243-283`<br>`backend/services/ed25519.py` | `register_release` 显式拒绝客户端上报 `signature_verified`（返回 `400 client_signature_verified_forbidden`），由纯标准库 RFC 8032 `verify_ed25519` 在服务端计算验签结果；Schema v11 迁移清零历史未绑定真签名数据。 |
| **有文件后果的准入状态机** | `backend/services/governance_service.py:427-538`<br>`backend/services/managed_installer.py:47-191` | 准入转换拒绝符号链接、setuid 与非普通文件，通过 `tree_hash()` 校验 `stage → commit → verify` 实际落盘哈希一致性，而非仅更新数据库状态布尔值。 |
| **工单闭环复测强制门禁** | `backend/services/governance_service.py:595-609` | 关闭 `incident` 强制查库验证同 `target_ref` + `detector_id`、在工单开启之后完成且 `finding_count == 0` 的 `retest_run`。 |
| **按版本验证的产品能力门控** | `backend/services/ingestion_service.py:123-134`<br>`endpoint/protocols.py` | 强制核验 `execution['product_version_source'] == 'registry'` 与能力矩阵，阻断端侧未验证产品/版本伪造 `allow/deny` 拦截记录。 |
| **诚实留空与冲突保留** | `backend/services/attribution_service.py:101-125`<br>`backend/services/governance_service.py:59-140,188-198` | `conflicts > 1` 时强制置 `selected=0`，分别统计 `no_candidate` 与 `ambiguous`；将 `intrinsic / runtime / exposure` 三维度独立评分并按证据强度封顶置信度。 |
| **端侧多 inode 游标与事务一致性** | `endpoint/audit.py:188-309`<br>`endpoint/outbox.py:60-72` | 按 `(source, inode)` 追踪多文件游标，消费先主后轮转，游标与 outbox 入队同事务提交；回滚后用独立连接落盘 `drops` 记录防账本丢失；`is_own_telemetry_argv` 过滤自监控噪声。 |

### 1.2 仍停留在原型 / 启发式 / 脆弱状态的环节

1. **Hook 存在明确 Fail-Open 缺陷与纯子串匹配绕过**（`endpoint/hook.py:42,46-47,114-124`）。
2. **归因引擎 `attribution-v2` 在长驻 Node 主进程与增量重算上已出现真实数据库误归因**（已在 `fusion.db` 四条真机执行上复现）。
3. **Linux Audit 规则覆盖仅限 6 个 `x86_64` 系统调用与单一 lab 目录 watch，且存在 `512 KB/s` 轮询吞吐上限**（`endpoint/audit.py:29-30,222,324`；`scripts/lab/install_audit.py:4,9`）。
4. **`EffectDiff`（`effect-diff-v1`）与 `DataFlow`（`dataflow-v1`）依赖环境变量注入桩、静态子串/域名表及时间窗兜底**（`endpoint/hook.py:67-68`；`backend/services/evidence_rules.py`；`backend/services/dataflow_service.py`）。
5. **控制面为单机 `ThreadingHTTPServer + SQLite + 全局 threading.Lock()`，无控制面主动下发/强隔离通道**（`backend/storage/repositories.py:66`）。

---

## 二、全链路威胁模型、TCB 边界与对抗绕过面分析

当前仓库缺少正式的 `Threat Model` 章节（仅 `docs/PROJECT-OVERVIEW.md` 列出非目标）。按系统安全标准核对代码可见以下 TCB 缺口与绕过面：

### 2.1 Hook 执行前拦截层（`endpoint/hook.py`, `endpoint/protocols.py`, `endpoint/install.py`）

- **高危 Fail-Open 逻辑漏洞（已源码实证）**：
  - `endpoint/hook.py:42`：条件写为 `if event['hook_event_type'] == 'pre_tool_use' and config.get('fail_mode') == 'deny' and version != 'unverified-changed':`。当宿主二进制元数据变化导致 `version == 'unverified-changed'` 时，直接跳过规则与阻断逻辑，保持 `decision = 'not_applicable'` 并返回空 stdout——**篡改产品二进制反而使 `fail_mode='deny'` 失效放行**。
  - `endpoint/hook.py:114-124`：`main()` 捕获所有 `Exception`（包括输入超 `8 MiB`、协议新字段触发 `unknown_protocol_fields`、未验证版本抛出 `ValueError('decision_protocol_not_verified_for_version')`、`Outbox` 满抛出 `CapacityExceeded`），仅向 `stderr` 打印错误 JSON 后 `return 0`（无 stdout 阻断 JSON）。对宿主 CLI 而言，空 stdout + exit `0` 等价于 **ALLOW**。
- **朴素子串绕过**：`hook.py:46-47` 对 `json.dumps(event['params'])` 做 `any(s in raw for s in deny_patterns)`。攻击者通过变量拼接（`a=/etc/; cat ${a}shadow`）、`base64` 编码、`$IFS` 拆分、通配符、`python3 -c` / `node -e` 即可直接穿过 `deny_patterns` 与 `ask_patterns`。
- **二进制指纹仅核 `stat` 元数据 & CLI 覆盖缺口**：`hook.py:27-31` 只核对 `[st_dev, st_ino, st_size, st_mtime_ns]`，不校验 SHA-256，也不覆盖 Node.js 运行时加载的外部 `.js` 依赖模块；`endpoint/install.py:131` CLI 参数 `choices=['codex', 'claude-code']` 尚未包含 `qwen-code`。
- **同 UID 自篡改悖论（Lack of Privilege Separation）**：`endpoint/install.py` 将 Hook 写入 `~/.claude/settings.json` / `~/.codex/config.toml`，`asgp-audit-collector.service` 与 Agent CLI 同以 `agentsec-lab` 用户运行。被提示注入的 Agent 执行任意命令即可修改 `config.json`、卸载 Hook、篡改 `outbox.db`（`0600` 同属主）或窃取 `device_token` 伪造遥测上报。

### 2.2 Linux Auditd 旁路采集层（`endpoint/audit.py`, `scripts/lab/install_audit.py`）

- **系统调用与协议覆盖大面积盲区**：
  - `endpoint/audit.py:29-30,62` 仅解析 `arch == 'c000003e'` 下的 6 个 syscall：`59(execve)`, `322(execveat)`, `42(connect)`, `2(open)`, `257(openat)`, `437(openat2)`。
  - **网络漏报**：无 `sendto(44)`、`sendmsg(46)`、`sendmmsg(307)`——**无 `connect` 的 UDP / DNS 隧道外发完全不可见**；`AF_UNIX` 传 fd（`SCM_RIGHTS`）同样隐身。
  - **文件与执行漏报**：无 `unlink/rename*/link*/symlink*`、`open_by_handle_at`、`splice/sendfile/copy_file_range`、`io_uring_*`、`memfd_create` / 内存 `ctypes`/`dlopen` 无盘执行；32 位兼容 syscall 在 line 62 直接丢弃。
  - **文件 Watch 范围极窄**：`scripts/lab/install_audit.py` 除 UID 级 exec/connect 外，专属目录 watch 仅针对 `/home/agentsec-lab/lab/asgp-p23`。
- **自身遥测过滤存在“搭便车”风险**：
  - `endpoint/audit.py:180-186` 通过读取 `/proc/<pid>/cmdline` 检查是否包含 `-m endpoint.flush/audit/hook`。攻击进程在运行态覆写自身用户态 `argv` 内存即可污染 `/proc/<pid>/cmdline`，诱导 `is_own_telemetry_pid` 将其整进程隐身；同时 `lines 269-273` 对同 `(pid, ppid)` 在 `[t_own, min(t_own+30, next_other_exec)]` 窗口内抑制非 execve 事件，存在并发共用父进程时的过滤波及面。
- **采集吞吐硬上限与审计停摆检测缺失**：
  - `collect_once` 单轮最多读取 `1 MiB`（line 226）且主循环每次无条件 `time.sleep(2)`（line 324），硬封顶采集速率为 **`512 KB/s`**；若单组审计事件超 `1 MiB` 抛出 `audit_record_exceeds_read_limit` 则不会推进游标。
  - `endpoint/coverage.py` 未读取内核 `auditctl -s` 的 `lost` / `backlog` 丢包计数；`fusion.db` 中 `coverage_reports` 为 `0` 行。

### 2.3 行为归因引擎 `attribution-v2`（`backend/services/attribution_service.py`）

- **结构性误归因实证（已由 `fusion.db` 直接复现）**：
  1. **长驻主进程锚点 + 增量 `ON CONFLICT DO UPDATE` 不删旧边**：`hook.py:71-94` 将 `hook_anchor` 绑定到 `qwen` Node 主进程 PID；当 `PreToolUse` 先到、`PostToolUse` 未到（`ended_at=None`）时，`attribution_service.py:60` 使用 `[start-1s, start+31s]` 宽窗口落库强边；后续 `PostToolUse` 闭合 `ended_at` 后重跑 `correlate()`，lines 97-102 的 `ON CONFLICT ... DO UPDATE` **只更新保留而不删除不再满足 `±5ms` 闭区间的历史错误边**，导致无关辅助进程被永久绑定给 `read_file`。
  2. **被拒绝/未结束调用 `+30s` 窗口爆炸**：`decision='deny'` 的调用不触发 `PostToolUse`，永远停留在 `ended_at=None`，同样触发 `[start-1s, start+31s]` 宽窗吞并宿主未来 31 秒子进程与网络外连。
- **Ambiguity DoS（并发降级绕过）**：同一主进程同时并发两个时间窗重叠的工具调用，`attribution_service.py:101-107` 检测到 `conflicts > 1` 会把相关边全部置 `selected=0`；虽然 `EffectDiffService` line 242 会兜底取 `intent_edges[:1]`，但 `GovernanceService` 只统计 `selected=1`，从而削弱运行时风险定级。

### 2.4 EffectDiff (`effect-diff-v1`)、DataFlow (`dataflow-v1`) 与其他边界

- **`ASGP_SOURCE_KIND` 信任根缺失**：`hook.py:67-68` 直接读取 `os.environ.get('ASGP_SOURCE_KIND')`，真实产品不原生传递上下文因果谱系。实库 `77` 条 `intents` 中 **`56` 条（72.7%）`source_kind IS NULL`**，其余 `21` 条均为测试人工注入环境变量。
- **IP vs 域名断层使 `TRUSTED_HOSTS` 在真实 Auditd 流量失效**：`audit.py:51-57` 解析内核 `SOCKADDR` 仅产生 IP，`evidence_rules.py:22-31` 的 `TRUSTED_HOSTS` 全是 18 个域名（如 `github.com`、`api.openai.com`）。真实 `linux-audit-v1` 的外连事件因为没有域名反向关联，一方面使 GitHub/CDN 正常流量匹配不到白名单导致误报，另一方面即使映射域名，`TRUSTED_HOSTS` 仍面临 **LOTS（Living-off-Trusted-Sites，如把密钥外传至攻击者私有 GitHub Gist / S3 / LLM API）** 零防御绕过。
- **`DataFlowService` 源头完全忽略 Auditd 真实文件读**：`dataflow_service.py:100-108` 只看 `intents.params_summary.resource_hints`，不检查已归因的 OS `file_access` 事件；真实脚本内部隐蔽读取 `.env.secret` 并外连公网 IP 时，如果 `run_shell_command` 的 `hints` 不包含该具体路径，`DataFlow` 100% 漏检（已在 `fusion.db` 实证）。
- **无地址 `network_connect` 错配**：实库 `18,232` 条 `network_connect` 中有 **`224` 条 `resource_host IS NULL`**；`effect_diff_service.py:118,276` 在 `read/write` 类别下无条件判为 `undeclared_side_effect` 并回退显示 `executable`。
- **Ed25519 元数据未绑定与审批 TOCTOU**：
  - `asset_service.py:311` 仅对 `content_hash.encode("ascii")` 验签，未将 `asset_id / version / publisher_id / published_at` 纳入签名载荷，存在合法签名被用于跨资产或历史版本回滚重放的风险。
  - `endpoint/approval.py:21` 仅绑定 `params_sha256`（工具参数 JSON 哈希），在最长 20s 人工审批窗口或放行前，若并发修改被调用脚本（如 `./run.sh`）或符号链接目标，仍存在间接引用 TOCTOU；`approval_service.py:34-38` 使用 `INSERT OR IGNORE` 回查复合键，对同一 `tool_call_id` 缺少单次消费作废控制。
- **无 `SessionEnd` 产品状态挂起 & 单机锁扩展瓶颈**：`qwen-code` 实测无 `SessionEnd` 事件，`fusion.db` 中 **20/20 条 `qwen-code` execution 全呈 `outcome='running'`**，连带 `DataFlowService` 只能落入 `last + 90s` 时间窗兜底；控制面 `ThreadingHTTPServer + SQLite + Storage._lock`（`repositories.py:66`）叠加 `audit_events` `30,000` 行截断与 `AttributionService.correlate` 全表拉取 `26,474` 条 `execution_id IS NULL` 事件入内存循环，在多机并发下存在明显锁争用与线性延迟劣化。

---

## 三、顶会方法学审查：合成评测集 vs 真实数据库（`fusion.db`）

### 3.1 合成集指标与真实运行现场的显著鸿沟

`docs/acceptance/*.json` 的全部亮点数字均来自作者编写的小规模合成轨迹，与 Host a 真实 `data/fusion.db` 在规模、字段完备度与噪声结构上差异极大：

| 对比维度 | 4 份合成评测脚本（`eval_*.py`） | Host a 真实库（`data/fusion.db` 实测） | 方法学差距与风险 |
| --- | --- | --- | --- |
| **样本与事件规模** | Attack `N=25 (18/7)`<br>Attr `10场景 13事件`<br>DataFlow `N=30 (15/15)`<br>EffectDiff `N=16 (8/8)` | `executions=61`, `intents=77`, `runtime_events=26,499`（`network_connect=18,232`, `process_start=8,122`, `file_access=120`, `hook_anchor=25`）, `event_attributions=307`（`process_tree=293`, `hook_id=14`）, `coverage_reports=0`, `publishers=0`, `asset_releases=0` | 真实库含海量宿主机背景系统调用，约 **98.8%+** 非锚点 OS 事件保持未归因留空；且签名发布表尚无真实业务记录。 |
| **`intent_ref` / `execution_id`** | `eval_effect_diff.py:266` 为所有合成事件预先填入 `intent_ref=intent_id` 与 `execution_id` | 全部 **`26,474` 条 `linux-audit-v1` 事件 `execution_id IS NULL` 且无 `intent_ref`** | 合成实验绕过了最脆弱的 `process_tree` 归因难度，实际只验证了高确定性 `hook_id` 支路。 |
| **`source_kind` 来源** | 100% 精准按实验分组注入 | 77 条 Intent 中 **`56` 条为 `NULL`（72.7%）**；其余 `21` 条由人工压测设置环境变量 | 运行时自动推导率为 0。 |
| **文档指标漂移** | — | `docs/PROJECT-OVERVIEW.md`、`docs/HANDOFF.md`、`docs/acceptance/2026-11-12-attribution-eval.md` 仍写旧版 **8 场景 11 事件：精度 1.00 / 召回 0.7143**；而最新 `docs/acceptance/attribution-eval.json` 为 **10 场景 13 事件：`selected` 精度 0.8333 / 召回 0.625、`hook_id` 精度 0.6667、`false_strong_rate=0.125`** | 存在文档数字滞后冲突，答辩直接引用旧数会现场穿帮。 |

### 3.2 `fusion.db` 四条真机执行只读回放实证（2026-11-14 实测）

| `execution_id`（产品） | 数据库状态与调用摘要 | `EffectDiffService.analyze` 实测 | `DataFlowService.trace` 实测 | 暴露的结构性问题 |
| --- | --- | --- | --- | --- |
| `exec_f62eb3bd997b5edf9e55bd000aaf5684` (`qwen-code`) | 2 intents（`read_file`, `run_shell_command`） | `undeclared_count=17`, `within_expected=32`（`read_file` 误报多条 `process_start`） | `flows=0` (`time_window`) | 长驻 Node 主进程并发辅助进程 + 增量重算未清理旧边导致 `read_file` 误报；DataFlow 未读 OS `file_access` 导致 0 检出。 |
| `exec_4ba2bf8ee2fa507c96d09d1879faeb8a` (`qwen-code`) | 2 intents（`read_file`, `run_shell_command`） | `undeclared_count=20`, `within_expected=49`（`read_file` 误报 `process_start`） | `flows=0` (`time_window`) | 同上：`read_file` 混入宿主子进程噪音，`DataFlow` 对 `.env.secret` 真实读取 + 外连彻底漏报。 |
| `exec_937f677660625781adc71487f1e473ba` (`qwen-code`) | 3 intents（最后一个 `run_shell_command` `ended_at=None`） | `undeclared_count=9`, `within_expected=16`（含 `read_file` 误报 `process_start` 及 `run_shell_command` 未声明 `network_connect`） | `flows=0` (`time_window`) | `02821dd` 过滤掉 ASGP 自噪声后 `read_file` 仍混入宿主机其他并行进程；`DataFlow` 仍漏报。 |
| `exec_a327161ede645869a326ffde47d9c8c6` (`codex`) | 1 intent（`Bash`, `decision='deny'`, `ended_at=None`） | `undeclared_count=7`, `within_expected=35`（共 42 条事件归因到已拒绝调用！） | `flows=0` (`time_window`) | **高危误报模式**：已被策略明确 `deny` 的调用因无 `PostToolUse`，触发 `+30s` 宽窗把宿主后续进程/外连算成该调用越界副作用。 |

### 3.3 四个现有评测脚本的关键方法学缺陷

1. **`eval_attack_set.py`**：仅运行 `skillspector --no-llm` 单引擎，未纳入其余已接入的 `snyk` / `mcp-scanner` / `aig`（LLM）；良性集仅 `N=7` 极简 Markdown（95% Clopper-Pearson FPR 置信上界高达 **41.0%**），缺乏多文件正常开发者技能测试。
2. **`eval_attribution.py`**：10 个场景贴合现有代码分支做循环验证（Circular Validation），但未模拟真实宿主机的同主进程并发噪声与 Pre/Post 增量到达顺序；且其中特意设置的 `collector_hint_points_at_wrong_intent` 场景已暴露 `hook_id` 精度降至 `0.6667`、`false_strong_rate = 0.125`。
3. **`eval_dataflow.py`**：规则贴合（Overfit 到 `TRUSTED_HOSTS` 与 `SENSITIVE_MARKERS`），在真机实库回放中呈现 **100% 漏检**（`flows = 0`）。
4. **`eval_effect_diff.py`**：对照基线 `_baseline_rule_only_detects`（line 267-270）人为只检查 `hints` 中的 5 个敏感字面串（Strawman Baseline）；且 A/B 两组不仅改变 `source_kind`，也同时改变输入 `events`，未能隔离证明 `source_kind` 自身的边际贡献。

### 3.4 缺失基线、消融实验与 2C2G 开销压测缺口

- **缺失消融矩阵**：缺少 **M0(Static-only) / M1(Hook-only) / M2(Audit-only) / M3(ASGP w/o source_kind) / M4(Full ASGP)** 在同一真实轨迹集上的定量拆解，以及与 `bubblewrap`/`Landlock` 沙箱、产品原生确认机制的横向对照。
- **系统性能与可靠性全无基线**：全仓库未测冷启动 `python3 -m endpoint.hook` 的 P50/P95/P99 工具调用附加延迟、未记录 `outbox.db` (`synchronous=FULL`) 三进程并发写锁耗时、未标定 `audit.py`（512 KB/s 上限）在突发编译/`npm install` 下的内核 `auditctl -s` `lost` 丢包率；同时 Host b `2C2G (1736 MiB / 0 Swap)` 在 `qwen-code` 下曾因内存不足触发 OOM/Swap 卡死，直接导致 `PostToolUse` 丢失并引发归因窗口退化。

---

## 四、简历 / 面试 / 答辩陈述“防穿帮”边界表

| 模块/陈述项 | 可自信硬刚的实证底座 | 绝对不能夸大（一问必穿帮）的红线 |
| --- | --- | --- |
| **工程规范与契约治理** | 完整 `460 passed`、`scan_hardcoded.py` 0 问题、`export-schemas.py --check` 通过；服务端拒收自报验签、准入 `tree_hash` 校验、工单 `retest_run` 门禁。 | 不能包装成“已落地大规模多机运维平台”：当前实库 `device_identities=1`，控制面到端侧无主动下发策略信道。 |
| **Ed25519 服务端验签** | 纯标准库 RFC 8032 验签，经 OpenSSL 交叉比对与单测验证，Schema v11 清零脏数据。 | 实库 `publishers=0`、`asset_releases=0`（尚无线上真实发布验签业务记录）；当前仅签 `content_hash` 未绑定 `asset_id/version`。 |
| **行为归因引擎** | 区分 `no_candidate` 与 `ambiguous` 拒绝强行瞎猜；`eval_attribution.py` 最新 10 场景 13 事件验证了冲突保留；真库对 98.8% 背景事件保持诚实留空。 | 不能按旧文档说“精度 1.00 / 零误归”（最新评测为 **0.8333 / 0.625** 且 `false_strong_rate=0.125`）；必须坦诚长驻主进程并发 + 重算竞态已在实库造成误归因。 |
| **EffectDiff（OS 副作用差分）** | 验证了“模型宣称作用域 vs OS 真实副作用”的检测范式，能抓出端侧静态词表看不到的隐蔽越界读取/外连。 | 不能拿合成集 `8/8 vs 0/8` 当真实世界检出率：合成脚本预填了 `intent_ref=intent_id`、基线仅查 5 词、且真机 `qwen-code` 在 `exec_f62eb3...` 上仍有并发与 `deny` 误报。 |
| **DataFlow（链路追踪）** | 实现基于敏感目录与可信域名/内网策略的路径级关联启发式与负样本过滤逻辑。 | **严禁称为“字节级污点追踪”**；目前只看 Hook 参数 `resource_hints` 不看 Auditd `file_access`，已在真机 `.env.secret` 测试集上出现漏报。 |
| **Attack Set 评测** | 验证 `SkillSpector` 在 25 条构造样本上检出 15/18，准确定位出“抽象外发 / 停审反取证 / 硬编码 token”3 类盲区。 | `N=25 (18/7)` 样本很小且未开 LLM/多引擎交叉验证，不可外推为“线上 0 误报”。 |
| **运营与闭环实例** | 跑通端到端链路：`admissions=2`、`incidents=1 (closed)`。 | 仅 1 条剧本演练工单（MTTR 19s 严禁当真实运营 KPI）。 |

---

## 五、14 道大厂 AI/Agent 安全面试官深水区拷打题

### Q1. 你的 `hook.py` 号称支持 `fail_mode=deny`，如果产品二进制被篡改或者输入超过 8MB 抛异常，到底会阻断还是放行？
- **设陷意图**：排查“Fail-Open vs Fail-Closed”工程底线。
- **踩坑回答**：“我们校验 `binary_fingerprints` 和 8MB 上限，出问题会抛错并记审计日志，在 `deny` 模式下保障安全。”
- **高分实证回答**：“目前存在一个已定位的 **Fail-Open 缺陷**。`endpoint/hook.py:42` 在 `if ... and version != 'unverified-changed'` 时跳过规则评估直接落回 `not_applicable`（返回空 stdout），而且 `lines 114-124` 的 `except Exception` 仅打 `stderr` 日志后 `return 0`——对 Claude Code/Codex/Qwen 来说空 stdout 即 **ALLOW**。修复方案非常简单直接：`fail_mode == 'deny'` 下的 `PreToolUse` 遇到 `unverified-changed` 或外层任何异常，必须显式输出符合协议的 `deny` JSON 并把二进制校验从 `stat` 元数据升级为 SHA-256。”

### Q2. 如果 Agent 执行 `bash -c "python3 -c '...'"` 直接用 UDP `sendto()` 做 DNS 隧道外传敏感文件，Hook 和 Auditd 谁能抓到？
- **设陷意图**：穿透“参数拦截 + 系统调用监控”表面宣传，考验 Linux 内核与协议层实战深度。
- **踩坑回答**：“Hook 就算漏掉脚本里的行为，Auditd 在底层监控进程与网络事件也能捕获到。”
- **高分实证回答**：“当前版本下 **两层都会漏掉无 `connect()` 的 UDP/DNS 外发**：(1) Hook 只对参数 JSON 做子串匹配，无法语义穿透 `python3 -c` 或 base64；(2) `endpoint/audit.py:29-30` 的 `SYSCALLS` 仅解析 `59/322/42/2/257/437` 六个 `x86_64` 调用，不包含 `sendto(44)/sendmsg(46)/sendmmsg(307)/io_uring_enter`，且 `scripts/lab/install_audit.py` 目前只对特定 lab 目录挂了 file watch。补强路线是扩充 `sendto/sendmsg` 及敏感目录 watch，或在容器化场景切到 eBPF LSM / seccomp-notify。”

### Q3. 你们在 `audit.py` 屏蔽 ASGP 自身遥测防止死循环，攻击者能否伪造自己成为“白名单进程”？
- **设陷意图**：对抗安全采集器自排除（Self-Exclusion Bypass）红队思考。
- **踩坑回答**：“我们的 `is_own_telemetry_argv` 会逐个检验 `-m endpoint.flush` 且禁止 shell 元字符，伪造不了。”
- **高分实证回答**：“`EXECVE` 阶段 `is_own_telemetry_argv` 确实严格防住了 shell 元字符，但 `is_own_telemetry_pid`（`endpoint/audit.py:180-186`）对已有 PID 直接读 `/proc/<pid>/cmdline` 判断是否包含 `-m endpoint.flush/audit/hook`。由于进程可覆写自身用户态 `argv` 内存污染 `/proc/<pid>/cmdline`，恶意进程确实存在利用窗口；此外同 `(pid, ppid)` 的 30 秒过滤窗也可能造成并发共父进程搭便车。生产中应废除不可信的 `/proc/<pid>/cmdline` 动态放行，改由专属独立服务 UID 或不可变 systemd cgroup 边界隔离。”

### Q4. 为什么真库 `exec_f62eb3...` 里一个无害 `read_file` 会被归因出 17 个 `undeclared_side_effect`？
- **设陷意图**：用真实现场问题检验是否真正分析过线上脏数据与竞态 Bug。
- **踩坑回答**：“可能是测试时宿主机正好有别的操作，`process_tree` 算法在评测集上是准确的。”
- **高分实证回答**：“这是我们在回放 `fusion.db` 时实证的根因级 Bug，由两件事叠加引起：(1) `qwen-code` 的 `hook_anchor` 挂在长生命周期 Node 主进程 PID 上，主进程并行派生的辅助进程（`node/python/git`）共用同一个 `ppid`；(2) `PreToolUse` 先到时 `ended_at=None`，`attribution_service.py` 先按 `[start-1s, start+31s]` 宽窗落库了关联边；等 `PostToolUse` 补充 `ended_at` 再次重算 `correlate()` 时，SQL 的 `ON CONFLICT DO UPDATE`（`lines 97-102`）只更新符合新条件的边，**不会删掉不再满足 `±5ms` 闭区间条件的旧错边**，导致 `read_file` 残留十几个无关 `process_start` 触发 `EffectDiff` 误报。修复方案就是收窄闭合窗的同时**显式清理过期无效边**。”

### Q5. 为什么 `attribution-eval.json` 写 `hook_id` 精度 `0.6667`、`false_strong_rate = 0.125`，而你们 `HANDOFF.md` 还在写 `1.00`？
- **设陷意图**：核查指标诚信度、文档一致性与对细节盲区的敏感度。
- **踩坑回答**：“`1.00` 是主分支结果，后来加边界测试时略有波动。”
- **高分实证回答**：“最新基线确实是 `10 场景 13 事件` 的 `selected: 0.8333 / 0.625`，旧文档（`PROJECT-OVERVIEW.md`/`HANDOFF.md`）未及时同步已列为文档缺陷整改项。`0.6667` 源于我们主动加入了负向抗干扰场景 `collector_hint_points_at_wrong_intent`：当采集器给出错误的 `intent_ref` 时，`attribution_service.py:47-50` 无条件信任 `HOOK_ID(0.99)` 且直接 `if not candidates` 跳过了进程树交叉核验，产出 1 条错误强边（`1/8 = 0.125`）。这证明 `hook_id` 不能盲信，必须与进程谱系及时间窗口交叉校验降权。”

### Q6. 如果攻击者让 Agent 并行调用两个工具（一个正常读 README，一个同时发起恶意 `curl`），你的冲突保留机制会怎么表现？
- **设陷意图**：利用系统“诚实留空（Ambiguity Abstention）”特性反打系统的“并发掩护（Ambiguity DoS）”。
- **踩坑回答**：“冲突事件会标记 `selected=0` 并保留两边的候选边，人工可以复核。”
- **高分实证回答**：“这里确实存在并发掩护降级风险：共享同一 Agent 主进程的两个并发工具调用一旦重叠，就会因 `conflicts > 1` 导致所有边的 `selected=0`。虽然 `EffectDiffService` 会回退取 `intent_edges[:1]`，但 `GovernanceService` 只认 `selected=1`，会使风险等级降档并淹没运营队列。仅靠主进程 PID 无法解开并发工具树，根本解法是为每个工具调用子进程注入独立隔离边界（如唯一环境变量令牌/子 cgroup/PTY 包装器）。”

### Q7. `DataFlowService` 怎样抓“脚本内部变量拼接读取私钥，再推送到攻击者自己的 GitHub Gist”？
- **设陷意图**：三连击——“参数与真实读脱节”、“LOTS 白名单绕过”、“域名/IP 断层”。
- **踩坑回答**：“我们的 `DataFlow` 会把敏感文件读和外连拼成链条，不过 GitHub 确实在可信列表里。”
- **高分实证回答**：“这组攻击在当前 `dataflow-v1` 下有三层断层：(1) **Source 漏看 OS 读**：`dataflow_service.py:100-108` 只从 Hook `resource_hints` 找源头，不查已归因的 Auditd `file_access`，已在真库 `exec_937f67...` 上实测返回 `flows=0`；(2) **IP/域名断层**：`auditd` 只产 IP，`TRUSTED_HOSTS` 是 18 个域名，真实流量上域名白名单无法直接命中；(3) **LOTS 风险**：若按域名粗放放行 `api.github.com` / `github.com`，攻击者向个人 Gist/恶意仓库外传敏感文件同样会逃逸。必须在 DataFlow 中接入真实 OS `file_access` 源、加端侧 DNS 解析关联，并对托管平台按路径/归属做细粒度管控。”

### Q8. 你们 `EffectDiff` 在评测集 8/8 vs 基线 0/8，怎么反驳“自己出题、给基线设弱智规则、还预填 `intent_ref`”的质疑？
- **设陷意图**：直击“循环验证（Circular Validation）”学术审查核心雷区。
- **踩坑回答**：“基线代表传统的关键词检测规则，这个 A/B 对比证明了语义与 OS 差分结合的必要性。”
- **高分实证回答**：“不能回避缺陷：(1) `eval_effect_diff.py:267-270` 仅用 5 个词查 `hints` 的确是稻草人基线，仅适合说明机理而非横向碾压；(2) `line 300+`（事件构建处）预填了 `intent_ref=intent_id` 绕开了真实归因难度；(3) A/B 组同时改了 `source_kind` 与 `events`，无法隔离出 `source_kind` 自身的边际贡献。下一步必须去掉预设 `intent_ref` 重跑、引入 AgentDojo/InjecAgent 真实负载轨迹，并用 4 层消融实验（Static/Hook/Audit/EffectDiff）给出严格对比。”

### Q9. `EffectDiff` 核心依据 `source_kind` 目前只是 `os.environ.get('ASGP_SOURCE_KIND')`，真实跑多轮对话时谁来给它赋真值？
- **设陷意图**：拷问上下文因果来源谱系（Source Provenance）的信任根。
- **踩坑回答**：“我们在控制面和 `hook.py` 用 `COALESCE` 保证了首次上报的 `source_kind` 不被后序覆盖。”
- **高分实证回答**：“实库 77 条 intent 里 **56 条为 `NULL`** 就说明当前产品原生协议不带来源谱系，`ASGP_SOURCE_KIND` 现阶段属于实验室注入桩。产品化落地两条路径：(1) 端侧在 `PreToolUse` 解析宿主只读 `transcript_path` 对话窗口，追踪当前推理轮次之前出现的最低信任来源（如 MCP 输出 / Skill 文档）做上下文污点继承；(2) 从架构上隔离执行环境，绝不从子进程可篡改的普通环境变量继承控制信任级别。”

### Q10. 如果攻击者把官方签过名的合法旧 Skill 签名 `(content_hash, sig)` 挪用到一个同名新资产或回滚旧漏洞版本，服务端 `verify_ed25519` 能拦住吗？
- **设陷意图**：密码学签名域隔离（Domain Separation）与版本降级攻击审计。
- **踩坑回答**：“能，改一点内容哈希就变了，Ed25519 验签就会报错 `signature_verification_failed`。”
- **高分实证回答**：“目前**拦不住跨资产替换与版本回滚**：`backend/services/asset_service.py:279` 传给 `verify_ed25519` 的明文仅是 `content_hash.encode('ascii')`，未绑定 `asset_id`、`version`、`publisher_id` 与有效期，且实库 `publishers=0, asset_releases=0` 尚未形成线上真实绑定记录。此外纯手写 `ed25519.py` 虽过 OpenSSL 交叉测试，仍需补充小阶点校验并切换标准规范结构体 `ASGP-REL-v1\0{asset_id}\0{version}\0{content_hash}\0{published_at}`。”

### Q11. 高危操作审批绑定了 `params_sha256`，真防住 TOCTOU 了吗？同一个 `tool_call_id` 重放怎么处理？
- **设陷意图**：审计审批状态机原子性与间接执行 TOCTOU 边界。
- **踩坑回答**：“算力端算 SHA-256、运营侧核对、服务端查一致性，参数篡改必拒，防住了 TOCTOU。”
- **高分实证回答**：“它防住了调用请求 JSON 本体的调包，但没防住**脚本/文件间接引用的 TOCTOU**（审批放行 `./run.sh` 的耗时窗口内被替换脚本内容或更换 symlink 指向），以及 **`approval_service.py:34-38` `INSERT OR IGNORE` 回查复合键对同一已批准记录的重复匹配**。生产补强需引入待执行脚本摘要绑定与审批令牌单次消费（one-time consume）机制。”

### Q12. 被监控 Agent 和端侧 Hook、`config.json`、`settings.json` 跑在同一个 Linux 用户下，被注入后直接改配置怎么防？
- **设陷意图**：拷问同权限端侧自保护的客观局限（Equal-Privilege Tampering）。
- **踩坑回答**：“我们在 `audit.py` 里有监控文件，且 `hook.py` 会在工具执行前检查。”
- **高分实证回答**：“在同 UID 拓扑下无法从强对抗角度防篡改——一旦在 `observe` 模式或 Hook 子串规则被绕过，子进程可直接修改同属主的 `config.json` 与产品配置文件。真实部署的唯一正道是**权限分离**：Agent 运行在低权限沙箱/容器或独立受限用户下，ASGP 配置、凭证、`outbox.db` 与 `auditd` 由 `root` 或独立安全账户持有，仅暴露最小特权通信接口并开启关键配置 FIM 写监控。”

### Q13. 适配 Claude Code / Codex / Qwen-code 三款产品时，遇到过什么破坏统一治理假设的坑？
- **设陷意图**：验证真实异构 Agent 接入的踩坑深度与工程诚实度。
- **踩坑回答**：“做了协议版本矩阵，Codex 不支持 ask 就自动转人工审批，全部打通了。”
- **高分实证回答**：“实战踩出两个直接影响上层状态机的问题：(1) Codex `0.166.0` 原生忽略 `ask` 决策，必须主动降级为控制面审批或硬拒绝，否则会产生‘表面在等确认、后台已偷跑’的假阻断；(2) **`qwen-code` 实测不发 `SessionEnd` 事件**，导致 `fusion.db` 里 **20/20 条 `qwen-code` 执行至今全部卡在 `outcome='running'`**，进而令资产运行态永久显示运行中、并迫使 `DataFlow` 长期依赖 `last + 90s` 宽时间窗。需要补基于心跳超时与 OS 主进程退出的执行回收机制。”

### Q14. 目前是 `ThreadingHTTPServer + SQLite + 全局 threading.Lock()`，如果接入 100 台端侧同时上报、外加同步人工审批，哪几处会先雪崩？
- **设陷意图**：系统容量规划、锁争用与架构演进能力考察。
- **踩坑回答**：“当前用于实验原型，后期可切 PostgreSQL 解决并发写。”
- **高分实证回答**：“会按四个节点依次引爆：(1) **同步审批阻塞连接与全局写锁**：`endpoint/approval.py` 每 `0.2s` 轮询 HTTPS 最长 `20s`，大量待审挂起线程加上心跳/上报争抢 `Storage._lock` 会锁死全部写入；(2) **全表扫描归因**：`AttributionService.correlate` 每次扫描同设备全部 `execution_id IS NULL` 事件（实库已达 `26,474` 条）做 Python 内存循环，百倍并发下延迟雪崩；(3) **端侧 `10,000` 条 Outbox 溢出丢包**：写入卡顿时 `auditd` 事件很快写满触发 `CapacityExceeded`；(4) **`audit_events` `30,000` 条截断上限**丢失操作审计历史。演进方案是拆分为异步入库队列 + 分区 PostgreSQL + `(host_id, device_id, occurred_at)` 复合索引 + 审批长连接/事件总线推送。”
