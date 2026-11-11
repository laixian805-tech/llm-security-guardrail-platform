"""HTTP 层：手写 `BaseHTTPRequestHandler` 路由、认证分发和错误格式。

只做协议适配；业务规则在 services/，数据契约在 domain/。`/api/v1` 承载
设备上报端点（设备令牌认证，不经控制台权限表）与控制台只读查询。
"""
