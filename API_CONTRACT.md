# ASGP API 契约草案

**状态：目标 API v1 草案。** 本文中的 `/api/v1/*` 是下一阶段契约，不代表当前原型已经实现。当前原型端点列在文末。

## 1. 通用约定

- JSON UTF-8；时间使用 UTC RFC 3339。
- 所有列表支持 `limit`、`cursor`；时间范围用 `from` / `to`。
- 所有写操作返回 `request_id`；端点上报支持 `Idempotency-Key`。
- `severity` 与 `confidence` 分开；未知严重度用 `unknown`，不能从 risk score 擅自推算。
- 原始扫描器输出由独立 `raw_report_ref` 引用，不在列表 API 中回传大段原文。
- 错误格式固定：

```json
{
  "error": {
    "code": "invalid_target",
    "message": "target is outside the enrolled workspace",
    "request_id": "req_..."
  }
}
```

## 2. 模型供应商

### `GET /api/v1/model-providers`

只返回 profile 元数据，不返回密钥：

```json
{
  "selected": "stepfun",
  "providers": [
    {
      "id": "stepfun",
      "name": "StepFun",
      "role": "primary",
      "selected": true,
      "codex_profile": {
        "wire_api": "responses",
        "base_url": "https://api.stepfun.com/step_plan/v1",
        "source": "codex_config"
      },
      "scanner_profile": {
        "wire_api": "chat.completions",
        "base_url": "https://api.stepfun.com/v1",
        "model": "step-5-preview",
        "secret_configured": false,
        "configured": false
      }
    },
    {
      "id": "xunfei",
      "name": "讯飞星火",
      "role": "candidate",
      "selected": false,
      "codex_profile": {
        "wire_api": "responses",
        "base_url": "https://maas-api.cn-huabei-1.xf-yun.com/v1",
        "source": "codex_config"
      },
      "scanner_profile": {
        "wire_api": "chat.completions",
        "base_url": "",
        "model": "",
        "secret_configured": false,
        "configured": false
      }
    }
  ]
}
```

### `POST /api/v1/model-providers/{provider_id}/probe`

用配置的密钥执行非敏感连通性/能力探测。响应只包含成功、延迟、协议和通过的 capability，不回显请求密钥或完整响应正文。Candidate 在 Probe 和能力验收通过前不进入默认路由。

**传输协议必须显式声明。** 当前 Codex 配置中的 StepFun/讯飞 profile 使用 Responses wire API；A.I.G 扫描 CLI 使用 Chat Completions。ASGP 的 provider adapter 要按 `wire_api` 选择协议，不能将 Responses 基础地址直接传给 Chat Completions 客户端。

供应商密钥优先来自 `STEPFUN_API_KEY`、`XUNFEI_API_PASSWORD` 等 Secret 环境变量；未覆盖时可从 Codex `config.toml` 对应 provider 的 Authorization Bearer header 在内存读取。密钥不会回传、写入数据库、报告、日志或 CLI argv。A.I.G 扫描 CLI 只接受 Chat Completions；讯飞候选必须通过对应的 Chat Completions endpoint/model 验收，不能把 Responses profile 直接当作扫描器接口。

## 3. 资产与扫描

### `POST /api/v1/assets/inventory`

接收经过设备身份认证的资产批次。服务端以设备注册记录为准确定 `host_id`、owner 和产品身份；客户端不能通过请求覆盖权威主机身份。

### `GET /api/v1/assets`

按 `asset_type`、`product`、`host_id`、`installation_state`、`activation_state`、`runtime_state`、`provenance` 和 risk level 筛选。

### `POST /api/v1/scans`

创建扫描任务，返回 `202 Accepted` 和 `scan_id`。请求样例：

```json
{
  "asset_ref": "asset_instance_...",
  "detector_id": "nvidia.skillspector",
  "target_ref": "workspace/skills/example",
  "mode": "static",
  "options": {"llm_analysis": false}
}
```

### `GET /api/v1/scans/{scan_id}` / `GET /api/v1/findings`

返回扫描状态、detector 版本、原始报告引用和标准化 Finding。扫描任务失败要与 `clean` 结果区分，不得将超时、解析错误或部分覆盖显示为无发现项。

## 4. 运行时事件

### `POST /api/v1/executions`

建立一次 Agent 执行上下文：`host_id`、`product`、`product_version`、`session_id`、关联 Asset Instance 和起止时间。

### `POST /api/v1/executions/{execution_id}/intents`

提交 Hook 观察到的操作请求。字段包含 `intent_id`、`tool_call_id`、`tool_name`、参数摘要/哈希、Hook 事件类型、decision 和时间。Secret 参数在端点本地先脱敏。

### `POST /api/v1/runtime-events:batch`

设备认证的批量事件写入。样例：

```json
{
  "host_id": "host_...",
  "collector_id": "linux-audit-v1",
  "events": [
    {
      "event_id": "evt_local_...",
      "execution_id": "exec_...",
      "event_type": "network_connect",
      "timestamp": "2026-11-10T00:00:00Z",
      "process": {"pid": 2314, "ppid": 2201, "executable": "curl"},
      "resource": {"host": "example.invalid", "port": 443},
      "intent_ref": null,
      "evidence_source": "linux_audit"
    }
  ]
}
```

服务端按 `host_id + collector_id + event_id` 幂等入库。`intent_ref` 可以为空；后续由 Attribution 服务追加一条或多条证据关联。

### `GET /api/v1/executions/{execution_id}/timeline`

返回 Intent、Runtime Event、Attribution、Finding 和 Policy Decision 按时间排序的调查视图。每条 Attribution 显示 `method`、`confidence` 和 `evidence_refs`。

## 5. 决策与治理

- `POST /api/v1/policies/evaluate`：输入明确的 intent/event/asset 上下文，返回 `allow | audit | confirm | block` 和 rule version。
- `POST /api/v1/admissions/check`：安装/启用前检查，不产生副作用。
- `POST /api/v1/admissions/{id}/approve`：记录有权限的人工审批。
- `POST /api/v1/admissions/{id}/commit`：执行带幂等键的实际安装/启用写入。
- `POST /api/v1/admissions/{id}/verify`：检查内容哈希、产品引用及产品反馈。
- `POST /api/v1/incidents` / `PATCH /api/v1/incidents/{id}`：创建/更新研判、定级、处置、复测和关闭记录。
- `GET /api/v1/incidents`：按 owner、severity、status、host 和时间筛选。

`PolicyDecision` 不等于执行成功；阻断成功必须另有 `EnforcementEvidence`。

## 6. 身份边界

- 控制台用户使用管理员认证与 RBAC；Provider Secret 仅由服务端 Secret 环境/Secret Store 读取。
- Data Plane 使用逐设备身份（mTLS 或可吊销设备令牌），服务端覆盖客户端提交的 host 身份字段。
- 设备令牌只在首次 enrollment 返回；服务端存摘要，可吊销和轮换。

原型已实现控制台用户认证、RBAC、请求审计和数据保留（见 7.1）；设备上报端点尚未开放，设备身份目前只能由管理员在控制台登记。

## 7. 当前原型端点

当前原型使用未版本化端点：`GET /api/health`、`GET /api/engines`、`GET /api/providers`、`GET /api/summary`、`GET /api/scans`、`GET /api/scans/{id}`、`POST /api/scans`、`POST /api/scans/import`。它只有扫描和报告归一化功能，尚未实现上面的 Asset、Runtime Event、Attribution、Policy、Admission 和 Incident API。

### 7.1 认证与授权

除 `POST /api/session` 和静态页面外，所有 `/api/*` 都要求控制台会话。未认证返回 401 并带 `WWW-Authenticate`，权限不足返回 403。未识别的 `/api` 路由同样要求认证，避免被用来探测端点是否存在。

| 方法 | 路径 | 需要的权限 | 说明 |
| --- | --- | --- | --- |
| `POST` | `/api/session` | 公开 | 登录，返回令牌并设置 `HttpOnly` Cookie |
| `DELETE` | `/api/session` | `read` | 登出并吊销当前会话 |
| `GET` | `/api/session` | `read` | 当前会话信息；前端用它判断会话是否仍有效 |
| `GET` | `/api/users` | `manage_users` | 用户列表，不含口令哈希 |
| `POST` | `/api/users` | `manage_users` | 创建用户，口令至少 12 位 |
| `PATCH` | `/api/users/{id}` | `manage_users` | 改角色或停用；不能操作自己的账号 |
| `POST` | `/api/users/{id}/password` | `manage_users` | 修改口令 |
| `GET` | `/api/devices` | `manage_users` | 设备列表 |
| `POST` | `/api/devices` | `manage_users` | 登记设备，明文令牌只返回一次 |
| `PATCH` | `/api/devices/{id}` | `manage_users` | 停用或吊销设备 |
| `GET` | `/api/audit` | `read_audit` | 审计事件，支持 `limit`、`actor_kind`、`action`、`since` |
| `GET` | `/api/scans/{id}/raw-report` | `read_raw_report` | 原始报告正文、哈希与字节数；列表和详情接口都不回传 |
| `GET` | `/api/retention` | `read` | 保留规则 |
| `POST` | `/api/retention` | `manage_retention` | 设置保留天数与开关 |
| `POST` | `/api/retention/prune` | `manage_retention` | 立即执行一次清理 |

角色权限：`viewer` 只有 `read`；`operator` 增加 `scan`、`probe`、`import_report` 和 `read_raw_report`；`admin` 再增加 `manage_users`、`manage_retention`、`read_audit`。设备令牌不属于这三档，它只证明上报资格。原始报告含扫描器整段输出、可能带目标源码片段，因此单独设 `read_raw_report`，列表和详情接口都不回传正文。
