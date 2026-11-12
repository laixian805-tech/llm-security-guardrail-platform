# P1 修复与 P2/P3 开始实施

2026-11-11。用户要求修复未通过项并启动 P2/P3；受控端仍为 116.62.28.177，开发机不装 Hook。

1. P1：增加绑定调用与参数哈希的 ASGP 控制面审批；产品原生 ask 能力不改写。审批批准→allow，拒绝/过期/离线→deny；测试端验证批准前证明文件不存在、批准后才执行。
2. P2：Linux Audit 解析、UID/规则过滤、原始参数省略、稳定事件 ID、SQLite 游标/outbox 同事务；测试端配置独立服务和受限规则。保留旧采集器，不把旧项目事件合并成新验收成果。
3. P2：EventAttribution 契约及存储，Hook ID/进程谱系/资源与时间弱候选；离线标注轨迹统计候选与 Precision/Recall，明确冲突与未归因。重放不能重复。
4. P3：风险三个维度、可解释策略结果、调用审批、准入检查/批准、Incident 证据与状态流转、真实 clean 重测关联；没有安装器时拒绝安装状态转换。
5. P3 下一片：受限托管目录的真实 stage/commit/verify/rollback、策略版本管理和完整 Asset/Detection/Incident/Policy 工作台。未实现部分不计验收通过。
6. 全部 schema 同步导出；每片运行有关测试和完整回归。部署前备份 SQLite，测试端保留安装前原始配置，默认 observe。

本计划记录实施顺序，不代表 P2/P3 已全量验收。最终结果与剩余工作写入本轮实测记录。

## 2026-11-12 进度

第 5 条的前三项已落地，完整回归 304 项全绿：

- 受管安装器 `backend/services/managed_installer.py` 与准入状态机改造（详见 IMPLEMENTATION_PLAN「P3 第二片」）。stage/commit/verify/reconcile/rollback 全部有真实文件系统后果；content_drift、installed_content_mismatch、installer_not_staged、实例互斥等失败路径均有测试覆盖。
- 策略版本管理：`PolicyRuleSet` + 原子激活 + 默认版本播种；evaluate 记录实际 policy_version，无活跃版本返回 500 不静默回退。
- 控制台工作台：资产中心、检测中心、风险与策略、准入安装、Incident 中心替代原「治理记录」占位页；准入每个转移、策略激活、Incident 流转都有界面入口，只读账号写操作置灰。真实 headless Chromium 走完整流程 40 项检查通过，证据见 [控制台实测](acceptance/2026-11-12-console.md)。
- schema v7（admissions.rollback_ref、policy_versions）、contracts/policy-version.schema.json、API_CONTRACT.md 已同步。

仍未完成：策略版本管理的影响评估与规则编辑器、托管目录磁盘配额与清理、真实产品安装器（当前安装目标是平台托管目录，不是产品加载路径）、真实 ASR/Utility/MTTR 指标。

## 2026-11-12 资产台账进度

第 5 条的资产清单与时间线整合已落地，完整回归 353 项全绿：

- schema v8：`assets` / `asset_instances` / `asset_releases` / `execution_findings` 四张表；三态不建列，查询时按准入事务与执行记录现算。
- `backend/services/asset_service.py` + `backend/api/v1.py`：登记幂等、列表筛选（含按派生值匹配的 activation_state）、追踪视图、执行↔发现项显式关联；`section_links` / `TRACE_LINKS` 把关联方式写进响应。
- 时间线接入 finding / admission / policy_decision，`sections_pending` 清空；控制台资产中心接入台账（登记表单、筛选、追踪视图）并渲染新分段。
- `tests/test_asset_ledger.py` 25 项：登记幂等与校验、秘密形状拒收、三态推导规则表（含真实准入往返）、追踪视图串联、权限（只读可看不可写、设备令牌 401）、v8 迁移断言（表存在、版本号为 8、asset_instances 无三态列）。
- 真实 headless Chromium 复核资产中心与运行时间线渲染，证据见 [资产台账实测](acceptance/2026-11-12-asset-ledger.md)。
