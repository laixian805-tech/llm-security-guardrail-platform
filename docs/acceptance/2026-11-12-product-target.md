# 准入安装落真实产品加载路径（2026-11-12）

本轮解决 P3 唯一"状态机声称已安装、但没有任何产品会加载它"的缺口：受管安装器原来只把包放进平台自己的 `data/managed/installed/`。现在多了产品加载路径这一落点，并且**验证判据来自产品会话本身**，不是文件存在。

## 改了什么

- `backend/services/product_installer.py`：按产品布局（`claude-code → ~/.claude/skills`、`codex → ~/.codex/skills`、`qwen-code → ~/.qwen/skills`）安装；目录名只允许单个安全分量；目标是符号链接直接拒绝；冲突时先快照旧版本再原子替换；`chown` 给目标用户，否则产品进程读不到。
- 准入状态机：`check` 接受可选 `product_id`（必须在配置绑定内，否则 400）；`commit` 在平台落盘后再写产品目录，产品侧失败会**回滚平台提交**，不留半成品；`verify` 增加产品侧校验；`rollback` 同时移除产品目录并恢复快照。
- schema v8 增列：`product_id` / `product_target` / `product_rollback_ref` / `product_loaded` / `product_verification`。历史记录保持 NULL，不回溯改写既有验收结论。
- `scripts/lab/product_load_probe.py`：可复现的真实加载探针。

## 验证判据的三态

`verify` 不是"文件在就算成功"：

| 结果 | 含义 | 状态机动作 |
| --- | --- | --- |
| `loaded=true`（`product_session`） | 产品会话识别并执行了该技能 | 标 verified |
| `loaded=false` | 产品明确回 `Unknown command` | 判 **failed**（`product_skill_not_loaded`） |
| `loaded=None` | 探测不可用：无 CLI / 不支持该产品 / 超时 / 缺凭据 | 标 verified 但记 `product_verification=filesystem:*`，**不声称已加载** |

超时和非零退出不算"产品否认该技能"——那是"没得出结论"，必须降级而不是判死。

## 实测证据（116.62.28.177，用户 agentsec-lab，Claude Code 2.1.152）

```
INSTALL  target=/home/agentsec-lab/.claude/skills/asgp-admission-demo
         owner=agentsec-lab:agentsec-lab  rollback_ref=first_install
VERIFY   level=product_session  loaded=true
         probe: claude -p /asgp-admission-demo --output-format text → "ASGP_ADMISSION_E2E_OK"
REMOVE   removed  target_exists_after=false
对照      卸载后 claude -p /asgp-admission-demo → "Unknown command: /asgp-admission-demo"
```

四方证据同时成立：文件真实落盘且属主正确、产品真的加载并执行了技能、卸载真的移除、卸载后产品真的不认。

复现：
```bash
python scripts/lab/product_load_probe.py --home /home/agentsec-lab --owner agentsec-lab
```

## 边界（本轮未成立的部分）

- **跨机安装不成立。** 控制面在 `43.139.77.64`，产品在 `116.62.28.177`。控制面无法直接写远端用户家目录，本轮验证是在产品同机完成的。要让控制台点一下就在测试端落盘，需要"控制面 → 端侧"的指令通道（P2），当前架构只有端侧向控制面上报的单向链路。
- 因此 `ASGP_PRODUCT_BINDINGS` 在控制面默认**不配置**；未配置时带 `product_id` 的准入检查会被拒绝（`product_targets_not_configured`），不会静默退化成只进平台存储。
- 只有 `claude-code` 声明了会话级探测。`codex` 的探测命令未实测，`verify` 会对它返回 `unsupported_for_product` 并降级为文件级——按项目一贯口径，没测过的能力不声明。
