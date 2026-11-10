# 第三方许可与署名

本平台作为扫描引擎编排层运行，目前没有把上游扫描器的源文件复制进平台目录。各引擎在独立虚拟环境中安装和执行，并继续适用各自的许可。

## A.I.G 署名

Tencent AI-Infra-Guard 使用 Apache-2.0 许可，仓库 `NOTICE` 对集成或衍生作品提出署名要求。产品文档、About 页面或发布说明中须包含以下原文：

> Based on Tencent Zhuque Lab AI-Infra-Guard

并附上原仓库链接：[Tencent/AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard)。

若后续发行包直接复制或再分发 A.I.G 源码，须保留上游 `LICENSE` 和 `NOTICE`。当前 NOTICE 中明确列出署名原文和仓库链接要求；没有单独写明额外的“禁止包装或品牌化”条款。本平台仍保留上游来源说明，避免来源不清。

## 已集成引擎许可

- NVIDIA SkillSpector：Apache-2.0；其仓库还包含运行时依赖的第三方软件声明。
- Snyk Agent Scan：Apache-2.0。
- Cisco MCP Scanner：Apache-2.0。
- ToolHive：Apache-2.0。
- Protect AI LLM Guard：MIT；上游仓库已归档。

本文件记录集成来源，不替代各组件的完整许可文本。若将扫描器打包进发行版本，须一并附上该版本的 `LICENSE`、`NOTICE` 和依赖声明。
