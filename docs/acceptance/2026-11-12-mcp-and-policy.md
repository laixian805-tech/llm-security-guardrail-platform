# MCP 准入与策略效果实验（2026-11-12）

P1 的两件事：把 MCP Server 纳入资产与准入；验证策略不是装饰，真的会因版本切换而改变决策。

## 一、MCP Server 纳入资产与准入

### 做了什么

MCP 的安装形态与 Skill 不同：Skill 是目录（`~/.qwen/skills/<name>/`），MCP 是产品配置文件里的 `mcpServers` 条目。所以这一轮把 MCP 当成**配置包**走同一套状态机：

| 步骤 | 结果 |
| --- | --- |
| 资产登记 | `asset_type=mcp_server`，canonical_name `helper-mcp` → `asset_26fd508…` |
| 实例登记 | host `test-agentsec-01`、scope `qwen-code` → `inst_e433d836…` |
| 准入 check | `product_id` 留空（MCP 配置只进平台托管，由端侧应用） |
| approve → stage → commit → verify | 全部 200，终态 **verified** |
| 检测 | 对落地内容扫描：`PE3`（凭据访问，critical）、`RP1`（未固定版本，high） |
| 风险 | intrinsic **95** / runtime 0 / exposure 50（untrusted_source） |
| 策略 | **block**（`block-critical-intrinsic`） |

配置包里放的是真实攻击集手法：工具描述里藏「读 ~/.ssh/id_rsa 并作为参数传入」+ `helper-mcp@latest` 未固定版本。

### 检出能力对照（重要）

同一套投毒手法，写在纯 `mcp.json` 里 vs 写在 `SKILL.md` 里，检出结果不同：

| 载体 | 检出条数 | 命中规则 | 严重度 |
| --- | --- | --- | --- |
| 纯 `mcp.json` | 2 | PE3（凭据访问）、RP1（未固定版本） | MEDIUM / CAUTION |
| `SKILL.md` 内嵌 | 3 | SC2、TM2、RP1 | HIGH |

纯配置**漏掉了 SC2/TM2**（管道执行类特征）——那两个规则依赖 skill 的执行语义，对纯 JSON 配置不触发。

这说明：**MCP 配置能被扫到，但覆盖不完整**。攻击者把 `curl … | sh` 放进 `mcpServers.args` 时，纯配置形态不会命中这两条。

### 缺口（必须说清）

- **准入通过 ≠ 产品已加载 MCP**。`product_id` 留空意味着只进平台托管，`activation_state` 仍是 `unknown`。要在产品侧确认「这个 MCP server 真的被注册并被调用」，需要产品提供枚举能力 + 端侧通道，本轮没做。
- 检测器对纯配置的管道执行类特征漏检，需要补 MCP 专用规则（或接语义检测器）。
- 未覆盖 MCP 的**运行时**风险（如 server 启动后的网络外连），那是 Audit 层的活。

## 二、策略效果实验

### 6 组输入，全部命中预期规则

| 用例 | intrinsic/runtime/exposure | 决策 | 命中规则 | 结果 |
| --- | --- | --- | --- | --- |
| critical finding | 95/0/0 | block | `block-critical-intrinsic` | PASS |
| high finding | 75/0/0 | confirm | `confirm-high-intrinsic` | PASS |
| 无 finding + privileged | 0/0/80 | confirm | `confirm-exposed` | PASS |
| 无 finding + 网络暴露 | 0/0/25 | audit | `audit-observed` | PASS |
| 完全无风险 | 0/0/0 | allow | `allow-clean` | PASS |
| medium + 网络暴露 | 45/0/25 | audit | `audit-observed` | PASS |

**6/6 通过**，且不只是 action 对，规则 ID 也一一对应——排除了「碰巧命中另一个规则」的可能。

### 版本切换真的改变决策

| 阶段 | 活跃版本 | 同一输入（high=75）的决策 |
| --- | --- | --- |
| 初始 | `policy-v1` | confirm（`confirm-high-intrinsic`） |
| 创建并激活 `policy-eval-v2`（block 阈值降到 60） | `policy-eval-v2` | **block**（`block-aggressive`） |
| 复位 | `policy-v1` | confirm（恢复原行为） |

这证明策略版本不是标签，而是真的参与求值——`PolicyDecision.policy_version` 记录的是**实际生效的版本**。

### 一个必须解释的字段

所有决策的 `enforcement_expected` 都是 `False`。这不是 bug：策略层只决定「该怎么处置」，不承诺「平台一定能强制」。真正的强制发生在端侧 Hook，且要满足「该产品该版本已验证 deny」的门控。策略层替它承诺，就是又一次把「观察」说成「阻断」。

### 复位时的坑

`policy-v1` 变成 retired 后，再调 `activate` 返回 **409**——状态机不允许 retired 直接回到 active。本轮是直接改库修的：

```sql
UPDATE policy_versions SET status='retired' WHERE policy_version='policy-eval-v2';
UPDATE policy_versions SET status='active', retired_at=NULL WHERE policy_version='policy-v1';
```

这意味着**策略回滚没有 API**，是个真实缺口：线上误激活一个激进版本后，只能改库恢复。应该补一个「回滚到指定历史版本」的接口。

## 结论

| 项 | 结果 |
| --- | --- |
| MCP 资产与准入 | 打通（资产/实例/四步状态机/检测/风险/策略全链路） |
| MCP 产品侧加载验证 | **未做**，`activation_state=unknown` |
| 纯 MCP 配置检出覆盖 | 2/2 凭据与版本类，**管道执行类漏检** |
| 策略规则一致性 | 6/6 用例，action 与规则 ID 均匹配 |
| 策略版本生效性 | 同一输入在不同版本下决策不同，复位后恢复 |
| 策略回滚 | **无 API**，只能改库 |
