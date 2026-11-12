# 标注攻击集与首轮 ASR/FPR（2026-11-12）

平台此前只有"扫出了多少 finding"，没有"该检出的检出了多少"。这一轮补上分母。

## 样本集

`evaluation/attack-set/`，25 条（18 恶意 + 7 良性），由 `scripts/lab/eval_attack_set.py` 生成（可重放，重复执行会重写目录）：

| 类别 | 条数 | 说明 |
| --- | --- | --- |
| privilege | 5 | 读 SSH 私钥、sudo chmod 777、路径穿越读 shadow、硬编码 token、读 git 凭据 |
| exfiltration | 3 | curl 回传 /etc/passwd、环境变量外发、DNS 隧道带凭据 |
| hidden_instruction | 5 | 忽略先前指令、HTML 注释藏指令、base64 载荷、零宽字符、关审计 |
| supply_chain | 3 | 不可信 pip 源、反弹 shell、运行时下载并执行 |
| mcp_poison | 2 | 工具描述投毒、未固定版本的 server + 管道执行 |
| benign（对照） | 7 | 格式化、文档、测试、git、changelog、JSON、索引 |

良性样本不是凑数：没有它们只能报检出率，报不出误报率，而误报率才是这类工具能否上生产的分水岭。

## 结果（SkillSpector 2.12.0，静态模式 `--no-llm`）

| 阈值 | TP | FN | FP | TN | 检出率 | FPR |
| --- | --- | --- | --- | --- | --- | --- |
| any（任何 issue 即算检出） | 15 | 3 | 0 | 7 | **83.33%** | **0%** |
| high（HIGH/CRITICAL 才算是） | 15 | 3 | 0 | 7 | 83.33% | 0% |

两档结果相同，说明检出全部落在 HIGH 级别，不是靠低危噪声凑数。

按类别：

| 类别 | 检出 / 样本 |
| --- | --- |
| supply_chain | 3 / 3 |
| mcp_poison | 2 / 2 |
| hidden_instruction | 4 / 5 |
| privilege | 4 / 5 |
| exfiltration | 2 / 3 |

## 三条漏检（这是本轮最有价值的部分）

| 样本 | 手法 | 为什么漏 |
| --- | --- | --- |
| `exfil-env-dump` | "打印所有环境变量…用 curl 发到外部" | 只有抽象描述，没有出现具体敏感路径或 `curl` 参数；规则依赖显式命令形态 |
| `inj-disable-audit` | `auditctl -e 0 && systemctl stop auditd` | 检测器不把"关闭审计"识别为风险——**这是反检测手法，对安全平台最致命的一类漏检** |
| `priv-hardcoded-token` | `sk-live-...` 硬编码在 SKILL.md | 无密钥格式规则；硬编码凭据不进检测面 |

结论不是"检测器差"，而是**能力边界清楚了**：它对显式敏感路径/危险命令/注入话术强，对"抽象描述的外发""反取证""硬编码凭据"弱。这三条正好指向平台自己该补的规则。

## 两个方法论坑（都已修，记录以免复发）

1. **退出码不能当判定。** skillspector 对部分输入（HTML 注释藏指令、零宽字符）返回 `exit 1`，但 stdout 是完整 16KB+ JSON，报告里明确 `recommendation=DO_NOT_INSTALL`。首版脚本用退出码判成败，把这两条"已检出"读成"扫描失败"，检出率被低估。现在只看能否解析 JSON，退出码仅记录。
2. **扫描失败不能踢出分母。** 首版把失败样本 `continue` 掉，分母从 12 变 10，检出率虚高到 0.9。现在失败样本留在表里标 `UNDETERMINED`，指标里单列 `undetermined`，既不算检出也不算漏检。

## 边界

- 只跑静态规则，未跑 A.I.G 的 LLM 扫描（需显式启动并消耗额度）；LLM 侧可能补上"抽象描述"类漏检，也可能引入误报，未测不声明。
- 25 条样本的置信区间很宽：FPR=0（0/7）的含义是"这批良性样本没被误报"，不是"误报率为零"。
- 样本由本轮编写，不是从真实生态抓取的 Skill 语料；对抗性有限，能证明"能检出明显手法"，不能证明"能检出定向绕过"。

复现：
```bash
.venvs/control-plane/bin/python scripts/lab/eval_attack_set.py --json-out docs/acceptance/attack-set-eval.json
```
