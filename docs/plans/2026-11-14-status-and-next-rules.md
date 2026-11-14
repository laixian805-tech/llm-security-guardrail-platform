# ASGP 项目现状与下一步推进规则

> **文档基线时间**：2026-11-14  
> **权威代码基线**：Host a（`43.139.77.64:/root/agent-security-fusion-platform`）分支 `asgp`，提交 `02821dd`  
> **运行拓扑**：Host a（控制面 + 公网 HTTPS 控制台） + Host b（`116.62.28.177`，`2 vCPU / 1736 MiB RAM / 0 Swap` 受控端点）

---

## 一、当前项目现状快照（Factual Status Snapshot）

### 1.1 最近已完成的核心工程里程碑

| 提交 / 阶段 | 核心交付内容 | 现状判定 |
| --- | --- | --- |
| `f3317d3`（P0-P3 基础闭环） | Ed25519 纯标准库服务端验签（Schema v11）、`SourceKind` 来源字段、`EffectDiff` (`effect-diff-v1`)、跨三款产品接入 | 服务端闭环已打通；线上尚未产生真实发布者/签名记录，真机并发下有误报待修 |
| `a78cae1`（Qwen 进程树兼容） | 适配 `npm .bin/qwen` 与 Node MainThread 进程树的 `hook_anchor` 识别 | Host b `qwen-code 0.26.8` 可正常触发钩子与 OS 关联 |
| `b08c17d` & `6c8bfbc`（控制台视觉重构） | 仿照 Wiz / Linear 的 Slate 视觉与信息密度收敛，合并诊断抽屉并恢复公网 HTTPS 可用性 | 已稳定运行于 `https://43.139.77.64/#runtime` |
| `02821dd`（端侧自噪声排除） | 在 `endpoint/audit.py` 过滤 `EXECVE/PROCTITLE` 及 `(pid, ppid)` 窗口内 ASGP 自监控噪声、过滤 `AF_UNIX`/`AF_NETLINK` 噪音；收窄已闭合调用直接子进程归因窗口 `[start-5ms, end+5ms]` | `exec_937f677660625781adc71487f1e473ba` 实测 0 漏出 ASGP Hook 噪声、`sent: 63, dead: 0`；测试达 `460 passed` |
| **公网端口收敛（2026-11-14）** | 清理 11-12 残留端口与多余 nginx proxy；仅保留 HTTPS `443`、HTTP `8000`（301 跳转 `443`）、SSH `22` 及环回内部服务 | 验证 `https://43.139.77.64/` 与 API 登录、`GET /api/v1/executions` 均返回 `200` |

### 1.2 在线服务、端口与主机资源实况

- **Host a（控制面 `43.139.77.64`）**：
  - `asgp-control-plane`（`active`）：监听 `127.0.0.1:8010`，占用空间约 `1.2G`（含 `data/fusion.db` `25M`、`fusion.db-wal` `3.7M`）。
  - `nginx`（`active`）：对外提供 `443` TLS 反向代理与静态资源、`8000` 跳转 `443`。
  - `postgresql` / `redis-server`（`active`）：底层基础设施常驻（当前 ASGP 主库仍使用 SQLite `data/fusion.db`）。
- **Host b（受控端点 `116.62.28.177`）**：
  - 硬件约束：**2 核 2G（`1736 MiB` 可用内存，`0 Swap`）**。曾因高并发下开 2G Swap 与 `qwen-code` Node 进程内存叠加导致卡死重启，**必须严格控制内存上限**。
  - 仅对外暴露 `22` 端口，控制面通信走本地 SSH 反向隧道 `127.0.0.1:18082`。

### 1.3 实时数据库基线与质量基线

- **自动化验证基线**（最近一次代码改动 `02821dd` 后实测）：
  - `./scripts/test.sh`：**`460 passed`**（含 `scan_hardcoded.py` `0` 问题、`export-schemas.py --check` 通过）。
- **`data/fusion.db` 实时业务表实数（2026-11-14 实测）**：
  - 资产与检测：`assets = 2`、`asset_instances = 2`、`detector_runs = 5`、`findings = 6`、`admissions = 2`、`incidents = 1 (closed)`。
  - 签名发布与设备：`device_identities = 1`、`publishers = 0`、`asset_releases = 0`、`coverage_reports = 0`。
  - 运行时执行与遥测：`executions = 61`（`claude-code`: 20 completed / 1 running；`codex`: 19 completed / 1 running；`qwen-code`: **20 running / 0 completed**）；`intents = 77`（其中 **`56` 条 `source_kind IS NULL`**）；`runtime_events = 26,499`（`network_connect = 18,232` [含 `224` 条 `resource_host IS NULL`]、`process_start = 8,122`、`file_access = 120`、`hook_anchor = 25`）；`event_attributions = 307`（`process_tree = 293`、`hook_id = 14`）；`audit_events = 30,002`。

### 1.4 专家评审暴露的当前 P0 级技术债（必须正视的现状）

1. **Hook 存在 Fail-Open 缺陷**（`endpoint/hook.py:42,114-124`）：二进制篡改状态 `unverified-changed` 或外层异常返回 `exit 0` 空 stdout，变相等同于允许执行。
2. **`AttributionService` 重算残留错边与被拒调用宽窗误报**：`ON CONFLICT DO UPDATE` 不删除过时旧边，`decision='deny'` 且 `ended_at=None` 的调用仍套用 `[start-1s, start+31s]` 宽窗——已在 `fusion.db` 中造成 `exec_f62eb3...`（`read_file` 17 条误报）与 `exec_a32716...`（已拒绝 `Bash` 产生 7 条越界告警）。
3. **`DataFlowService` 只看参数不看 OS 文件读**：对真机 `.env.secret` 隐蔽读取 + 公网 IP 外连（`exec_937f67...`/`exec_4ba2bf...`）漏检率 `100%`（`flows = 0`）。
4. **`SourceKind` 依赖环境变量 & DNS/LOTS 缺位**：真实 `intents` 中 `72.7%` 无 `source_kind`；Auditd 纯 IP 事件导致域名白名单在实库空转，且缺乏 LOTS 防护。
5. **文档与实验基线漂移 & 2C2G 吞吐无压测**：`HANDOFF.md`/`PROJECT-OVERVIEW.md` 仍写旧归因指标 `1.00 / 0.71`（最新 `attribution-eval.json` 为 `0.8333 / 0.625`）；合成集 `eval_effect_diff.py` 预填了 `intent_ref` 且对比基线过弱；缺乏消融实验、公开数据集验证与 `512 KB/s` 吞吐压测。

---

## 二、下一阶段推进硬性规则（Execution Rules）

在后续每一轮功能开发、缺陷修复、端侧压测与对外汇报中，**必须严格遵守以下五条红线规则**：

1. **【规则一：实证口径隔离红线】**
   - 严禁把 `scripts/lab/eval_*.py` 的小规模合成数据指标（如 `100%`、`0% FPR`、`8/8`）宣称为生产环境真实准确率或零误报。
   - 任何对外输出或论文/面试描述的性能、检出率指标，必须同时附带**样本量（N）、是否预填 `intent_ref`、是否真实宿主机背景噪声**三项前提，并报告真实库回放复核结果。
2. **【规则二：文档与基线同步红线】**
   - 凡修改归因算法、检测规则、协议或更新 `docs/acceptance/*.json` 基准数据，**必须在同一提交内**同步更新 `docs/PROJECT-OVERVIEW.md`、`docs/HANDOFF.md` 与对应验收文档中的指标数字，消除“文档写 `1.00`、JSON 写 `0.8333`”的口径打架。
3. **【规则三：2C2G 端侧资源与稳定性红线】**
   - Host b 严格维持 `0 Swap` 或低风险限制，禁止在 `1736 MiB` 实例上并发拉起多个重型 Node Agent 或重负载测试。
   - 端侧任何采集/Hook 改动，必须核验：(a) `asgp-audit-collector` 内存不超过配额 `96M`；(b) `outbox.db` 无持续堆积/丢包（`dead=0`）；(c) 实测 `auditctl -s` 的内核 `lost` / `backlog` 指标。
4. **【规则四：Fail-Closed 与核心安全不变量红线】**
   - 任何涉及策略裁决、验签与归因的代码修改，不得引入静默 `Fail-Open` 分支；`PreToolUse` 在 `fail_mode='deny'` 下遇异常必须显式返回阻断决策。
   - Ed25519 验签必须绑定完整资产元数据作用域；归因重算必须在边界收缩时清理过期边；已被 `deny` 拦截的意图不得套用长时后置归因窗。
5. **【规则五：公网暴露与提交验收红线】**
   - Host a 仅保持 `https://43.139.77.64/`（`443` / `8000→443`）与管理 `22` 对外暴露，禁止遗留临时测试端口或未鉴权调试进程。
   - 每次提交与推送前，控制面必须跑通 `./scripts/test.sh` 与 `python3 scripts/lab/scan_hardcoded.py`（`0` 问题）；每次涉及端侧 Hook/Audit 的修改必须在 Host b 完成一次真机小流验证并检查 `https://43.139.77.64/#runtime` 页面正常呈现。

---

## 三、下一步可执行改进路线图（P0 → P1 → P2）

### 第一梯队 P0（高 ROI 止血修复 + 真实基础补齐，优先实施）

| 编号 | 任务内容 | 对应改造位置 | 完成验收标准（Definition of Done） |
| --- | --- | --- | --- |
| **P0-1** | **修复 Hook Fail-Open 与二进制校验加强** | `endpoint/hook.py`<br>`endpoint/install.py` | 1) `fail_mode=='deny'` 时 `unverified-changed` 及所有 `PreToolUse` 异常均显式 stdout 输出 `deny` JSON；2) `install.py` 补全 `qwen-code` 选择支；3) 增加对应 Fail-Closed 单测。 |
| **P0-2** | **消除真库两类高危 `EffectDiff` 误报** | `backend/services/attribution_service.py`<br>`backend/services/effect_diff_service.py` | 1) `correlate()` 闭合窗口更新时清理已不满足时间条件的历史 `process_tree` 边；2) `decision=='deny'` 的 Intent 严禁触发 `+30s` 宽窗扩展（仅允许即时极窄窗口或零后置归因）；3) 过滤 `resource_host IS NULL` 无效 `network_connect` 不报越界；4) 重算 `exec_f62eb3...` 与 `exec_a32716...`，确认 `read_file` 误报和已拒绝 `Bash` 的越界误报清零。 |
| **P0-3** | **打通 `DataFlowService` 的 OS `file_access` 源头与可信IP/域名断层** | `backend/services/dataflow_service.py`<br>`backend/services/evidence_rules.py` | 1) `DataFlowService` 同时读取已归因 OS `file_access` 敏感路径，不再仅看 `resource_hints`；2) 补齐 `/etc/shadow`、`/proc/*/environ` 等敏感规则并收紧 `.env.example` 类误匹配；3) 重跑 `exec_937f67...` 与 `exec_4ba2bf...`，能检出 `.env.secret` → 公网外连链路。 |
| **P0-4** | **完善 Ed25519 元数据域绑定与实库零记录填补** | `backend/services/asset_service.py`<br>`backend/services/ed25519.py` | 签名原文升级绑定 `asset_id + version + content_hash`，在控制面补入不少于 1 条真实合法签名 `publisher + asset_release` 验证记录（使实库不再是 `0/0`），同步校验单次审批消费防重放。 |
| **P0-5** | **修复 `eval_effect_diff.py` 方法论自证并对齐全仓库文档口径** | `scripts/lab/eval_effect_diff.py`<br>`docs/HANDOFF.md`<br>`docs/PROJECT-OVERVIEW.md` | 1) 去掉 `eval_effect_diff.py` 中对 `intent_ref` 的人工预填，改用真实进程树轨迹验证；2) 统一全仓库文档为 `attribution-eval.json` 最新实测数字（`10 场景 13 事件`），彻底消除数字打架。 |

### 第二梯队 P1（外部基准引入、消融实验与 2C2G 开销压测）

1. **引入外部真实/公开基准数据集**：对接 **AgentDojo** / **InjecAgent** 间接提示注入与工具投毒任务、收集真实多文件恶意/良性 Skill 样本（目标恶意 $\ge 60$、良性 $\ge 60$，逐步扩充至 $\ge 100$）。
2. **补齐内部四层消融（M0 Static → M1 Hook → M2 Audit → M3 w/o `source_kind` → M4 Full ASGP）与外部沙箱/原生基线对照**，证明每一层的真实边际增益。
3. **2C2G 端侧微基准与良性工作流误报压测**：
   - 在 Host b 测量 Hook 冷启动 P50/P95/P99 延迟，优化 `audit.py` 固定 `sleep(2)` 导致的 `512 KB/s` 瓶颈，并把 `auditctl -s` 内核 `lost`/`backlog` 纳入 `endpoint/coverage.py` 上报 `coverage_reports` 表；
   - 跑通标准开发者良性负载（`pytest`、`git`、`npm`），输出 **每千次工具调用误报率（FP / 1k calls）**；
   - 增加基于心跳超时 / 主进程退出的 `execution` 自动收敛，解决 `qwen-code` 无 `SessionEnd` 导致的 `running` 挂起问题。

### 第三梯队 P2（进阶工程演进与学术级规范）

1. **非环境变量 `SourceKind` 谱系推导**：解析端侧只读 `transcript_path` 对话轮次状态自动判定工具来源信任级别，替代 `ASGP_SOURCE_KIND` 实验室桩。
2. **多机可扩展控制面与强权限隔离架构**：推动 `Storage` 向 PostgreSQL + 异步入库演进、审批通知升级推送机制、端侧推进低权限 Agent 与安全采集器账号隔离，以及扩展 `sendto/sendmsg` / eBPF 覆盖与统计置信区间报表自动化。
