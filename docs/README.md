# 文档入口

_LLM Security Guardrail Platform 的操作、展示与实现说明索引 · Last updated: 2026-06-17_

---

## 📋 推荐阅读顺序

| 顺序 | 文档 | 适合场景 |
| ---- | ---- | -------- |
| 0 | [平台使用手册](./platform-user-manual.md) | 想一次看懂平台定位、完整操作、AutoDL 恢复、答辩讲法 |
| 1 | [小白操作指南](./beginner-operation-guide.md) | 第一次跑实验、生成报告、做 RAG 投毒演示 |
| 2 | [项目展示说明](./project-showcase-guide.md) | 答辩、面试、路演、写项目总结 |
| 3 | [实现说明](./implementation-notes.md) | 查看当前后端模块、设计默认值和评测方向 |

---

## 🎯 当前项目主线

本项目当前最重要的主线是：

```mermaid
flowchart LR
    accTitle: Documentation Reading Path
    accDescr: Recommended documentation path from beginner operation through project showcase and implementation notes

    beginner([👤 小白操作]) --> showcase[📋 项目展示]
    showcase --> implementation[🔧 实现说明]
    implementation --> next([🔄 继续迭代])

    classDef start fill:#ede9fe,stroke:#7c3aed,stroke-width:2px,color:#3b0764
    classDef process fill:#dbeafe,stroke:#2563eb,stroke-width:2px,color:#1e3a5f
    classDef success fill:#dcfce7,stroke:#16a34a,stroke-width:2px,color:#14532d

    class beginner start
    class showcase,implementation process
    class next success
```

先跑通一轮 `paired-run`，再生成正式报告，然后围绕 RAG 投毒、工具越权和失败样本分析继续加固。
