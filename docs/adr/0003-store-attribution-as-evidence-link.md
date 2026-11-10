# 将行为归因保存为证据关系

状态：已采纳。

Runtime Event 不要求直接填写 `intent_id` 外键。ASGP 用独立 Attribution 关系保存候选 Intent、关联方法、置信度和支持证据；没有可靠匹配的 Event 保持未归因。这样可以保留歧义和多个竞争解释，避免把时间窗口相近误报成确定因果。
