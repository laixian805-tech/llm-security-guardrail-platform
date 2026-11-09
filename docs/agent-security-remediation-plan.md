# Agent Security 资产口径与供应链治理修复计划

_状态：P0 资产身份、release 字段、生命周期拆分、准入审计和运行时 enforcement 记录已实施；完整安装事务与 MCP 生命周期仍待补 · 2026-11-09_

这份计划针对当前 `llm-security-guardrail-platform` 的五个修复顺序：

1. 资产模型改为 logical asset + physical instance + content hash + carrier/state。
2. 缓存或未安装资产只进入库存，不产生风险告警。
3. 静态 finding 改为可解释的风险评分，并保留原始 verdict。
4. 为域名、URL、公网 IP 和文件哈希建立可复核的 ThreatBook enrichment 链路。
5. 把 admission gate 接到安装、启用和 Skill 读取路径。

这份文档只定义领域边界、接口和验收标准，不把当前历史统计当成新的事实。

## 0. 当前基线

当前工作树已有 Agent Security 的 scanner、Hook、collector、SQLite、FastAPI 和前端页面，但资产表仍按单一 `asset_id + path` 表示资产。ThreatBook 已有 IP/SHA256 的 shadow 查询和缓存；域名查询仍被跳过。准入 gate 已有独立 CLI 检查器，但尚未接入真实的安装或启用路径。

**本轮实施进度：**资产记录现有 `logical_id`、`instance_id`、`content_hash`、`carrier`、`state`、`scope` 字段；旧 SQLite 行会迁移并保守标为 `discovered`（明确缓存位置标为 `cached`）；`/assets/summary` 已分离逻辑资产、副本、缓存仓库/插件/内容定义；缓存、vendor 和 synthetic scan 不再写入实时告警事件；前端默认列出纳管状态并单独显示缓存汇总。仍需在 P0 验收中用真实配置引用验证启用状态推导，并完成缓存仓库实机计数对照。

风险评分现已输出 `risk_score`、`ranking_score` 和逐项 breakdown；scanner verdict 保持独立。ThreatBook 已从扫描 finding 提取 URL/domain、公网 IP 和 SHA256，写入查询审计表并提供查询 API；domain 请求默认不出站，只有 `THREATBOOK_DOMAIN_ENABLED=1` 才会调用已配置端点。Admission 有管理员 check API，Hook 会对已识别 Skill 的读取执行 block/ask，并在 post-hook 使用证据到达后标记 active。仍待完成：在用户产品安装/启用配置变更的实际写入点执行 check + commit；实机确认 ThreatBook domain endpoint 和账户权限。

评审修订已同步：logical asset 现在区分 publisher/namespace，release 绑定 version/content hash/source，instance 绑定 release；安装、激活、运行状态独立；准入 decision 写入不可变记录；Hook 动作写入 runtime enforcement 记录。当前仍不把文件写入视为完整 commit，下一阶段需要不可变 release 目录、原子 pointer switch、幂等键、补偿和 reconciliation。

P0 测试机运行时实验见 `docs/agent-security-runtime-test-plan.md`；P1/P2 路线和 execution origin 见 `docs/agent-security-p1-p2-roadmap.md`。

历史数字 `542 / 599 / 125 / 459` 属于 v1 路径计数，完成第 1、2 项后必须标记为废弃，不能继续作为当前资产规模或检出率。

## 1. 领域模型

### 1.1 五个互不替代的概念

| 概念 | 含义 | 计数用途 |
| --- | --- | --- |
| Logical asset | 产品、类型、名称组成的跨路径逻辑资产 | 统计真实资产数量、跨副本去重 |
| Physical instance | 某台主机上某个载体路径的副本 | 追踪安装、缓存、漂移和删除 |
| Content | 文件或目录规范化后的内容身份 | 归并同内容副本、发现 hash 漂移 |
| Carrier | 资产所在的载体类别 | 区分缓存、内置、用户安装、项目本地、依赖 |
| State | 从证据推导出的生命周期状态 | 区分发现、缓存、安装、启用、活跃、禁用、移除 |

身份规则：

```text
logical_id  = sha256(product | kind | canonical_name)
instance_id = sha256(host | carrier | canonical_path)
content_hash = sha256(normalized_content)
```

`asset_id` 在迁移期间保留为兼容字段，新的 API 不再把它当作逻辑身份。

### 1.2 Carrier 规则

| carrier | 证据 | 是否计入 installed |
| --- | --- | ---: |
| `marketplace_cache` | 父链含插件市场缓存目录，并存在仓库元数据或多插件目录 | 否 |
| `product_builtin` | 存在 `.system` 或产品 marker | 是，标记 builtin |
| `user_installed` | 产品 Skills/Plugin 目录，且存在产品配置引用或安装记录 | 是 |
| `project_local` | 项目内 `.claude/skills` 等本地目录 | 是，作用域为项目 |
| `vendor_dependency` | `node_modules`、`site-packages`、`venv` 等依赖树 | 否 |
| `synthetic` | 实验室 fixture 路径 | 仅在 synthetic 统计中计入 |
| `unknown` | 证据不足 | 不得自动推断为 installed |

Carrier 是来源分类，不是信任结论。`marketplace_cache` 仍可扫描，但只能进入缓存库存。

### 1.3 State 规则

状态按证据降级或升级，不由路径名称直接猜测：

```text
discovered -> cached -> installed -> enabled -> active
                              \-> disabled -> removed
```

- `discovered`：只发现了文件或目录。
- `cached`：确认属于市场或插件缓存，但没有产品安装引用。
- `installed`：有产品配置引用、安装记录或明确的用户安装证据。
- `enabled`：在产品启用列表或有效配置中被引用。
- `active`：有 Hook 事件、进程加载或最近使用证据。
- `disabled`：曾启用但已有明确禁用证据。
- `removed`：历史实例不再存在；保留历史记录，不从审计库物理删除。

没有证据时最高只能是 `cached`，不能直接升级为 `installed`。

## 2. 实施顺序与验收

### 2.1 P0：资产双 ID、carrier、state 和 summary

**修改范围**

- `backend/app/agent_security/models.py`
- `backend/app/agent_security/store.py`
- `backend/app/agent_security/assessment.py`（只保留 provenance/carrier 分类）
- `backend/app/agent_security/scanner.py`
- `backend/app/agent_security/inventory.py`
- `backend/app/agent_security/api.py`
- `web/src/agentSecurityModel.js`、`web/src/App.jsx`、`web/src/i18n.js`

**存储迁移**

在 `assets` 增加：

```text
logical_id TEXT NOT NULL
instance_id TEXT NOT NULL UNIQUE
content_hash TEXT
product TEXT
carrier TEXT NOT NULL DEFAULT 'unknown'
state TEXT NOT NULL DEFAULT 'discovered'
scope TEXT NOT NULL DEFAULT 'host'
last_used_at TEXT
removed_at TEXT
```

迁移必须可重复执行。旧行先按 `host/kind/name/path` 生成 instance，按 `kind/name` 生成 logical；无法确认 carrier 的旧行设为 `unknown + discovered`，不能批量标为 installed。

**API**

- `GET /api/agent-security/assets`：支持 `state`、`carrier`、`kind`、`host`、`logical_id` 过滤。
- `GET /api/agent-security/assets/summary`：返回 `discovered/cached/installed/enabled/active` × `kind` × `carrier`，并返回 `legacy_metrics`。
- `GET /api/agent-security/assets/{logical_id}`：返回逻辑资产和全部 instances。

summary 必须附带：

```json
{
  "current": {"installed": {}, "enabled": {}, "active": {}},
  "inventory": {"discovered": {}, "cached": {}},
  "legacy_metrics": {
    "value": {"skills": 542, "targets": 599},
    "status": "obsolete_v1_path_count"
  }
}
```

**验收标准**

1. 同一 Skill 在缓存目录和用户安装目录产生一个 logical asset、两个 instances。
2. 同内容不同路径的 instances 共享 `content_hash`。
3. 缓存市场折叠为仓库级库存摘要，不进入 installed 默认列表。
4. `.system` 内置 Skill 计入 installed，但 carrier 为 `product_builtin`。
5. UI 默认显示 installed/enabled/active，缓存只显示一行聚合摘要。
6. 重复扫描不新增 logical asset 或 instance。

### 2.2 P0：未安装资产不产生告警

**规则**

- scanner 仍可以扫描缓存，结果写入 inventory。
- 只有 `state in {installed, enabled, active}` 的实例才创建 `scan_finding` 风险事件。
- `discovered/cached/vendor_dependency` 的 finding 保留为库存信号，不能进入 alert/block 分母。
- `synthetic` 使用独立统计，不混入真实安装资产。

**修改范围**

- `scanner.py`：发现阶段返回 carrier/state 证据，不在发现阶段制造 `unregistered_source` 告警。
- `store.py`：`record_scan()` 按 state 决定是否写入风险事件。
- `api.py`：summary 和 stats 分开返回 inventory findings 与 enforcement alerts。
- `web/src/agentSecurityModel.js`、`App.jsx`：分开显示库存和告警。

**验收标准**

1. 扫描 600 个缓存定义不会产生 600 条未登记告警。
2. 已安装但未登记的 Skill 仍产生 S16，并进入风险队列。
3. 统计接口同时返回 `inventory_findings` 和 `enforcement_alerts`，禁止复用一个总数。
4. 旧的 459 alert 不再作为当前有效率分母。

### 2.3 P1：风险评分和 breakdown

**修改范围**

- `backend/app/agent_security/assessment.py`
- `backend/app/agent_security/models.py`
- `backend/app/agent_security/store.py`
- `backend/app/agent_security/api.py`
- `backend/tests/test_agentsec_assessment.py`

**评分规则**

```text
score = clamp(sum(unique_rule_weight)
              + chain_bonus
              + provenance_penalty, 0, 100)

critical = 25, high = 15, medium = 8, audit = 3
S08 + S11/S20 = +20
S04 + S06 = +15
反混淆后命中 = rule_weight * 1.2
S16 未登记来源 = +5
未启用资产 = score * 0.6（只影响排序）
active 资产 = score * 1.0
```

同一规则只计一次；三次以上命中按 1.5 倍封顶。评分永远不能写入 `confirmed_malicious`。

**输出结构**

```json
{
  "score": 63,
  "band": "high_risk_candidate",
  "breakdown": [
    {"rule_id": "S08", "weight": 25, "reason": "sensitive read"},
    {"rule_id": "S20", "weight": 15, "reason": "external URL"},
    {"chain": "S08+S20", "weight": 20, "reason": "read then external access"}
  ],
  "assessment": "high_risk_candidate"
}
```

**验收标准**

1. 相同 finding 输入得到稳定分数和稳定 breakdown。
2. 单独 S08 不触发链路 bonus。
3. S08 与外联规则组合时 bonus 可见且可解释。
4. `confirmed_malicious` 只能来自人工 review 或高置信 TI + 本地证据。
5. 未启用资产排序降低，但不会从 API 隐藏。

### 2.4 P1：ThreatBook IOC enrichment

**修改范围**

- `backend/app/agent_security/threat_intel.py`
- `backend/app/agent_security/ti.py`
- `backend/app/agent_security/store.py`
- `backend/app/agent_security/api.py`
- `backend/tests/test_agentsec_threat_intel.py`
- 新增 `ioc_queries` 表和 IOC 提取模块

**IOC 流程**

1. 从已解码、已脱敏的 finding evidence 提取 URL、domain、公网 IP、SHA256。
2. 规范化、去重，私网 IP、内网域名、路径和原始文本不出站。
3. IP、domain、SHA256 分类型查询；domain 端点必须由显式配置和账户能力开关启用。
4. 每次查询落 `ioc_queries`：IOC、类型、provider、查询时间、cache hit、返回 verdict、confidence、错误原因。
5. `clean` 只代表 IOC 在查询时的信誉，不清除本地 finding，也不自动降级风险。

**API**

- `POST /api/agent-security/ti/lookup`：管理员触发单 IOC refresh。
- `POST /api/agent-security/assets/{logical_id}/ti/refresh`：刷新该逻辑资产关联 IOC。
- `GET /api/agent-security/ti/queries`：查看可复核的查询记录，不返回 API key。

**验收标准**

1. URL 中的 domain 能进入查询队列；domain 未启用时返回明确 `unsupported_account`，不伪造查询成功。
2. 同一 IOC 在 TTL 内命中缓存且不消耗预算。
3. 查询记录包含时间、类型、结果、缓存命中和失败原因。
4. 私网/内网 IOC 不出站也不消耗预算。
5. TI clean 不会把本地 `high_risk_candidate` 自动改成 clean。

### 2.5 P1：Admission gate 接入真实生命周期

**修改范围**

- `backend/app/agent_security/admission.py`（现有检查器）
- `backend/app/agent_security/cli.py`
- `backend/app/agent_security/api.py`
- `backend/app/agent_security/hook.py`
- 产品安装/启用适配器所在模块
- 新增 admission API 和集成测试

**门禁条件**

- logical asset、instance、content hash 可确定。
- registry 登记和 hash 精确匹配。
- carrier 不能是 marketplace cache 或 vendor dependency。
- state 必须有 installed/enabled 的证据。
- high risk / confirmed malicious 一律拒绝。
- 未签名资产默认拒绝；若兼容旧资产允许 registry/hash 例外，必须显式配置并写审计事件。

**API**

- `POST /api/agent-security/admission/check`：返回 allow/block、checks、reason、logical/instance/content 身份。
- `POST /api/agent-security/admission/commit`：仅在 check 通过后写入 installed/enabled 证据。

**Hook**

- 对产品配置引用变更做 pre-change admission check。
- 对可疑 Skill 目录读取做同步阻断或 ask。
- Hook 输出只使用产品适配器协议；admission 结果不能绕过现有 fail-closed 逻辑。

**验收标准**

1. 未登记、hash 漂移、高风险、缓存路径默认返回 block。
2. 已登记且 hash 匹配的安装返回 allow，并产生审计记录。
3. check 未通过时不能写入 enabled 状态。
4. 重复 commit 幂等，不能生成重复 instance。
5. 离线时本地 gate 仍能阻断；平台 API 不可用不会自动放行。

## 3. 实施依赖和交付顺序

```text
P0 双 ID/carrier/state
  -> P0 未安装不告警
  -> P1 评分 breakdown
  -> P1 IOC enrichment
  -> P1 admission lifecycle
```

每一步完成后都要保留旧字段的兼容读取，但禁止新代码继续依赖路径型 `asset_id` 作为逻辑身份。

## 4. 历史口径处理

文档和 UI 必须把旧数字标记为：

> v1 path-count metric — obsolete; retained only for historical comparison.

修正后的报告至少同时给出：

| 维度 | 旧口径 | 新口径 |
| --- | ---: | ---: |
| 扫描定义数量 | 599 targets | discovered/cached inventory |
| 真实纳管资产 | 未区分 | installed/enabled/active logical assets |
| 告警数量 | 459 alerts | installed/enabled enforcement alerts |
| 高风险数量 | 125 blocks | scored high-risk candidates with breakdown |

旧数字不得静默改写为新数字；必须保留来源、时间和计算方式。

## 5. 并行协作边界

资产模型、store migration、API summary 和前端分层属于同一条主线，应该由一个会话连续完成。评分、TI 查询审计和 admission 集成可以在 P0 schema 稳定后继续，但不得在 schema 变更期间各自修改同一张 `assets` 表。每次切换会话前记录当前迁移版本、API 响应样例和未完成验收项。
