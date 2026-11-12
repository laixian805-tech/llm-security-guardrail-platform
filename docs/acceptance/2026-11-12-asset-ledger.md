# 资产台账与时间线整合实测记录（2026-11-12）

本轮把资产中心从「产品能力矩阵 + 执行聚合」升级为真实台账，并把 finding / policy_decision / admission 接进运行时间线。核心约束是**状态只能来自平台真正持有的证据**：安装状态由准入事务推导，运行状态由执行记录推导，启用状态没有证据来源、恒为 unknown，客户端声明的状态一律拒绝。受控端仍为 116.62.28.177，开发机不装 Hook；本节所有结论来自开发机上的真实服务与真实 headless Chromium 会话。

## 验证方式

- 起真实 HTTP 服务（临时 SQLite 库 + 临时托管目录 + 固定管理员口令），通过 HTTP 完成资产/副本/内容版本登记、执行与意图上报、发现项关联、风险评估与求值、准入检查。
- headless Chromium（Playwright 驱动 Chromium 1248）登录控制台：登记资产、渲染台账与筛选、打开追踪视图、切到运行时间线渲染四个分段。
- 判定标准：服务端状态真的变化、界面显示的派生状态与证据一致、关联方式在响应和界面里都可见。界面文案不计入证据，但"这里没有证据"这类边界标注必须在场。

## 结果

自动化测试 25 项（`tests/test_asset_ledger.py`）加完整回归 353 项全绿（7 项按既有条件跳过）；浏览器复核资产中心与运行时间线渲染通过，无未捕获异常（仅登出后探测会话产生的 401，属预期）。

| 面 | 实测结果 |
| --- | --- |
| 登记幂等 | 同名同类型同产品的逻辑资产重复登记返回同一 asset_id 与 `duplicate: true`；同名换产品是新逻辑资产；副本按（资产，主机，产品作用域）去重，重复登记只补空 install_path 并刷新 last_seen_at，不分裂出第二个副本 |
| 输入校验 | asset_type 非法、缺 canonical_name、未声明字段、content_hash 非 64 位小写十六进制、signature_verified 非布尔、published_at 非时间、未知 asset_id 均返回 400/404；秘密形状输入返回 400 `suspected_secret_parameter` |
| 安装状态 | 准入事务走到 committed/verified/reconciled 记 installed；failed 记 unknown（不重新 verify 说不清磁盘上是什么）；rolled_back 到 first_install 记 absent，恢复到提交前快照记 installed；只有 check/approved/staged 或无事务时记 unknown。规则表参数化进测试 |
| 运行状态 | 上报 outcome=running 的执行记 running，收尾后记 stopped，从未被任何执行引用记 unknown |
| 启用状态 | 恒为 unknown。提交 `activation_state` 返回 400；`GET /api/v1/assets?activation_state=enabled` 返回空列表，`?activation_state=unknown` 返回全部——筛选按派生值匹配，参数不被悄悄忽略 |
| 追踪视图 | 一条真实链路上 asset/releases/instances/admissions/executions/findings/policy_decisions/incidents 九段齐全；findings 带 linked_by/link_note，重复关联幂等且始终标 `association: analyst_linked` |
| 时间线 | finding / admission / policy_decision 三个分段按时间进入 entries，`sections_pending` 为空；响应带 `section_links` 逐段说明匹配方式 |
| 控制台 | 资产中心出现台账表（三态、准入/执行计数、追踪按钮）、筛选表单与登记表单；追踪视图按分段列出内容版本、副本三态、准入、执行、发现项、策略决定、Incident；运行时间线渲染四类条目并展示已接入分段与关联方式 |
| 控制台筛选 | 八种筛选组合逐一复核（installation_state installed/unknown、runtime_state running/stopped、query 命中/未命中、asset_type skill/mcp_server），结果与 API 一致；提交筛选不会整页刷新 |
| 多副本状态 | 同一资产两个副本处于不同运行状态时，运行列显示"未知 / 运行中"而不是挑一个 pill 蒙过去 |
| 权限 | viewer 可读台账但不能登记（写控件置灰），设备令牌访问台账 401 |

界面截图（开发机临时库）：资产中心与运行时间线各一张，台账三态为 未知/未知/运行中，时间线四条条目分别为策略决定、准入、Hook 意图、发现项。

## 设计取舍

- **三态不落库。** 库里没有任何 installation/activation/runtime 列（测试断言 `asset_instances` 无这三列）。存一份"声明值"就会出现"看起来已安装"被当成已安装的路径；现算的代价是每次查询多两次 IN 查询，台账规模下可接受。
- **存量自由文本引用不回溯。** `executions`/`admissions` 里的 `asset_instance_id` 是 P1 遗留字段，没有外键。v8 只建新表，不 backfill：查得到就呈现，查不到按未登记处理，不猜。
- **启用状态不作为筛选盲区。** 平台没有产品加载证据，`activation_state` 恒为 unknown。筛选器按派生值匹配而不是忽略该参数——忽略会让"没有已启用的资产"在界面上显示成"全部资产"。
- **发现项关联是显式登记，不是自动归因。** `POST /api/v1/executions/{id}/findings` 记录 actor_id 和 note，响应标 `analyst_linked`；时间线和追踪视图都把这一点写进 `section_links` / `TRACE_LINKS`，避免把字符串匹配读成采集器证明的因果。

## 仍未实现（不计验收通过）

- 策略版本管理的影响评估（改规则会翻转哪些历史决定）与规则编辑器（当前是 JSON 文本框 + 模板）。
- 托管目录的磁盘配额与清理。
- 真实 Skill/MCP 安装器：当前安装目标是平台托管目录，不是产品加载路径；准入带 product_id 时的 `product_loaded` 在探测不可用时是 None（未验证）而非 False。
- 真实 ASR / Utility / MTTR 指标。
- 测试端 116.62.28.177 的控制台访问与两产品接入未在本轮复跑；本轮验证在开发机完成。
