"""P1 路由：与既有控制台 API 共用 HTTP 服务，设备凭据独立校验。"""
import re
from urllib.parse import parse_qs, unquote
from services.ingestion_service import IngestError

EXECUTION = re.compile(r"^/api/v1/executions/([^/]+)/(intents|timeline)$")
ASSET = re.compile(r"^/api/v1/assets/([^/]+)$")
EXECUTION_FINDING = re.compile(r"^/api/v1/executions/([^/]+)/findings$")
# 端侧探测结果回传：数据面在自己主机上做真实加载验证，把证据交回控制面。
# 控制面进程往往连不到被测主机，所以这条链路是端侧主动回传，不是控制面推送。
PRODUCT_VERIFICATION = re.compile(r"^/api/v1/admissions/([^/]+)/product-verification$")


def is_device_route(method, path):
    if path == '/api/v1/approval-requests' and method == 'POST':
        return True
    if path.startswith('/api/v1/approval-requests/') and method == 'GET':
        return True
    # 产品加载验证由端侧执行并回传，用设备身份认证，不用控制台会话。
    if PRODUCT_VERIFICATION.fullmatch(path) and method == 'POST':
        return True
    match = EXECUTION.fullmatch(path)
    return method == "POST" and (path in ("/api/v1/executions", "/api/v1/runtime-events:batch")
        or bool(match and match[2] == "intents"))


def route(handler, method, parsed, ingestion, timeline, assets):
    path = parsed.path
    match = EXECUTION.fullmatch(path)
    asset_match = ASSET.fullmatch(path)
    finding_match = EXECUTION_FINDING.fullmatch(path)
    if path == '/api/v1/assets':
        if method == 'GET':
            handler._send(200, assets.list_assets(**_asset_query(parsed.query)))
        elif method == 'POST':
            handler._send(200, assets.register_asset(handler._body()))
        else:
            return False
        return True
    if asset_match and method == 'GET':
        handler._send(200, assets.trace(unquote(asset_match[1])))
        return True
    if path == '/api/v1/asset-instances' and method == 'POST':
        handler._send(200, assets.register_instance(handler._body()))
        return True
    if path == '/api/v1/asset-releases' and method == 'POST':
        handler._send(200, assets.register_release(handler._body()))
        return True
    if finding_match and method == 'POST':
        handler._send(200, assets.link_execution_finding(unquote(finding_match[1]),
                                                        handler._body(),
                                                        handler._actor().user_id))
        return True
    if path == '/api/v1/runtime-events' and method == 'GET':
        query=parse_qs(parsed.query)
        host=(query.get('host_id') or [None])[0]
        if not host:
            raise IngestError('host_id_required')
        handler._send(200, {'events': ingestion.events.list_for_host(host,limit=200)})
        return True
    if method == "POST" and is_device_route(method, path):
        body = handler._body()
        device_id = handler._device.device_id
        if path == "/api/v1/executions":
            result = ingestion.execution(device_id, body)
        elif path == "/api/v1/runtime-events:batch":
            result = ingestion.batch(device_id, body)
        else:
            result = ingestion.intent(device_id, unquote(match[1]), body)
        handler._send(200, {**result, "request_id": handler._request_id})
        return True
    if method == "GET" and (path == "/api/v1/executions" or (match and match[2] == "timeline")):
        query = parse_qs(parsed.query)
        try:
            limit = min(200, max(1, int(query.get("limit", [100])[0])))
        except ValueError:
            raise IngestError("invalid_limit") from None
        if match:
            result = timeline.get(unquote(match[1]), limit=limit, cursor=query.get("cursor", [None])[0])
        else:
            result = {"executions": ingestion.executions.list(limit=limit,
                host_id=query.get("host_id", [None])[0], product=query.get("product", [None])[0])}
        handler._send(200, result)
        return True
    return False


# 资产台账列表的筛选参数。activation_state 也按派生值过滤：平台没有产品加载
# 证据，它恒为 unknown，所以只有 unknown 查得到东西，enabled/disabled 必然
# 空结果——不能因为"查不出东西"就把参数悄悄忽略，那会让界面以为没有已启用的。
ASSET_FILTERS = ("asset_type", "product", "host_id", "installation_state",
                 "runtime_state", "activation_state", "provenance", "query")

# 状态类过滤参数必须落在枚举内。以前 activation_state 恒为 unknown，任何取值
# 都只会静默返回全量或空集；现在它有真实取值，非法值必须报错，否则调用方会
# 把"拼错的状态名"读成"没有这类资产"。
STATE_FILTERS = {
    "installation_state": ("unknown", "absent", "installed", "broken"),
    "runtime_state": ("unknown", "idle", "running", "stopped"),
    "activation_state": ("unknown", "disabled", "enabled"),
}


def _asset_query(raw: str) -> dict:
    params = parse_qs(raw)
    filters = {}
    for name in ASSET_FILTERS:
        value = (params.get(name) or [None])[0]
        if not value:
            continue
        allowed = STATE_FILTERS.get(name)
        if allowed is not None and value not in allowed:
            raise IngestError(f"invalid_{name}")
        filters[name] = value
    try:
        limit = min(200, max(1, int((params.get("limit") or [100])[0])))
    except ValueError:
        raise IngestError("invalid_limit") from None
    filters["limit"] = limit
    return filters
