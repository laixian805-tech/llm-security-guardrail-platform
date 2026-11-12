# 激活状态接入产品证据、时间线准入加窗口（2026-11-12）

上一轮资产台账留了两个口子：`activation_state` 恒为 unknown、时间线把实例历史上所有准入都挂到每条执行上。同一轮里产品路径准入又新增了 `product_loaded` 证据，于是这三件事可以合成一件做。

## 1. activation_state 现在有证据来源

判据只有一条：**产品会话真的认识这个 skill**。文件在、哈希对、verify 通过，都只是必要条件。

| 最近一次带 `product_id` 的准入 | activation_state | 含义 |
| --- | --- | --- |
| `verified`/`reconciled` 且 `product_loaded=true` | `enabled` | 产品会话确认加载 |
| `product_loaded=false`（产品回 Unknown command） | `disabled` | 产品明确不认 |
| `rolled_back` | `disabled` | 已撤销，产品侧内容被移除或回退 |
| `verified` 但 `product_loaded=null` | `unknown` | 探测不可用（无 CLI/超时/缺凭据）——未验证，不冒充已启用 |
| `committed`/`staged` 等未 verify | `unknown` | 事务没走完 |
| 没有 `product_id` | `unknown` | 只进平台托管存储，产品侧不存在"加载"这件事 |

实现要点：只看带 `product_id` 的事务（未声明产品目标的记录不该影响启用判断），按 `updated_at` 取最近一条，不做"回溯找上一次 enabled"。

## 2. 时间线准入限定在执行窗口内

原实现 `WHERE asset_instance_id=?` 全量拉，后果是同一个实例做过「v1 安装 → v2 升级 → v3 回滚」后，**每条执行的时间线里都出现全部三次准入**，也读不出"这次执行时装的是哪个版本"。

新判据：事务活跃区间 `[created_at, updated_at]` 与执行窗口 `[started_at, ended_at]` 有交集。

| 情况 | 是否保留 | 理由 |
| --- | --- | --- |
| 窗口内 created 并落定 | 保留 | 这次执行期间发生的准入 |
| 窗口前 created、窗口后仍 updated | 保留 | 跨窗口进行中，与本次执行有交集 |
| 窗口前就早已 updated | 排除 | 与这次执行无关 |
| 执行未结束（`ended_at` 为空） | 以当前时间为窗口右界 | 仍能看到窗口内发生的准入 |

时间比较统一解析成 tz-aware：历史数据混过 `Z` 结尾格式，直接比字符串会错序。

## 3. 过滤参数不再静默

`?activation_state=enabledd` 这类拼错的状态名以前会返回空集，被读成"没有这类资产"。现在三个状态参数都校验枚举，非法值返回 400。

## 验证

`tests/test_activation_window.py` 16 项，覆盖：六种派生组合、窗口内/跨窗口/窗口前三种时间关系、`Z` 后缀时间、未结束执行、非法过滤参数。

全量回归：**376 passed**（原 360 + 新增 16），端点回归 8 passed。

## 边界

- 机制已接通，但生产库里 `admissions` 仍为 0 —— 没有真实准入事务，`activation_state` 全部是 `unknown`。要看到 `enabled`，需要跑一次带 `product_id` 的完整准入，且产品侧探测可用。
- 跨机仍不可用：控制面在 a、产品在 b，控制面写不了远端 home。`enabled` 只能在产品同机时产生。
- Qwen 端侧未接完：真实模型额度 402，`product_loaded` 对它拿不到 `true`。
