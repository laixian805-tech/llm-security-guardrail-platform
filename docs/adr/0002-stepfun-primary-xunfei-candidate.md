# StepFun 为主用供应商，讯飞保留候选

状态：已采纳。

ASGP 的模型供应商接口默认选择当前 Codex 配置中的 StepFun profile，并保留讯飞星火 profile 供后续兼容性验证。供应商配置来源提供 provider ID、基础地址和 wire API；StepFun/讯飞各自的 Authorization Bearer header 可从 Codex config 在内存读取，并可分别由 `STEPFUN_API_KEY`、`XUNFEI_API_PASSWORD` 覆盖。密钥绝不回显或持久化。Provider Adapter 显式区分 OpenAI Responses 与 Chat Completions，避免把 A.I.G 扫描器需要的 Chat Completions 客户端指向 Responses 接口。
