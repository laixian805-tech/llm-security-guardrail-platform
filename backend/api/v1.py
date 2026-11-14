"""P1 路由：与既有控制台 API 共用 HTTP 服务，设备凭据独立校验。"""
import re
from urllib.parse import parse_qs, unquote
from services.ingestion_service import IngestError

EXECUTION = re.compile(r"^/api/v1/executions/([^/]+)/(intents|timeline)$")
ASSET = re.compile(r"^/api/v1/assets/([^/]+)$")
PUBLISHER_REVOKE = re.compile(r"^/api/v1/publishers/([^/]+)/revoke$")
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
    # 覆盖度对账同样由端侧上报：只有端侧知道自己本想送多少、丢了多少。
    if path == '/api/v1/coverage-reports' and method == 'POST':
        return True
    match = EXECUTION.fullmatch(path)
    return method == "POST" and (path in ("/api/v1/executions", "/api/v1/runtime-events:batch", "/api/v1/runtime-events:ingest-async")
        or bool(match and match[2] == "intents"))


def route(handler, method, parsed, ingestion, timeline, assets, coverage=None, async_ingest=None):
    path = parsed.path
    match = EXECUTION.fullmatch(path)
    asset_match = ASSET.fullmatch(path)
    finding_match = EXECUTION_FINDING.fullmatch(path)
    if path == '/api/v1/coverage-reports' and method == 'POST':
        # host_id 取设备行的绑定值，绝不采信请求体里的：否则一台设备可以
        # 把丢失率算到别人头上，或者把静默的采集器洗成正常的。
        host_id = ingestion.identity(handler._device.device_id)['host_id']
        handler._send(200, coverage.record(handler._device.device_id, host_id, handler._body()))
        return True
    if path == '/api/v1/executions:reap-stale' and method == 'POST':
        body = handler._body() if int(handler.headers.get('Content-Length') or '0') > 0 else {}
        stale_seconds = body.get('stale_after_seconds', 1800)
        if not isinstance(stale_seconds, int) or isinstance(stale_seconds, bool) or stale_seconds < 60:
            raise IngestError('invalid_stale_after_seconds')
        prod = body.get('product')
        if prod is not None and not isinstance(prod, str):
            raise IngestError('invalid_product_filter')
        handler._send(200, ingestion.executions.reap_stale(stale_after_seconds=stale_seconds, product=prod))
        return True
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
    if path == '/api/v1/publishers':
        if method == 'GET':
            handler._send(200, assets.list_publishers())
        elif method == 'POST':
            handler._send(200, assets.register_publisher(handler._body()))
        else:
            return False
        return True
    revoke_match = PUBLISHER_REVOKE.fullmatch(path)
    if revoke_match and method == 'POST':
        handler._send(200, assets.revoke_publisher(unquote(revoke_match[1])))
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
        status = 200
        if path == "/api/v1/executions":
            result = ingestion.execution(device_id, body)
        elif path == "/api/v1/runtime-events:ingest-async":
            if async_ingest is None:
                result = ingestion.batch(device_id, body)
            else:
                result = async_ingest.enqueue(device_id, body)
                status = 202
        elif path == "/api/v1/runtime-events:batch":
            result = ingestion.batch(device_id, body)
        else:
            result = ingestion.intent(device_id, unquote(match[1]), body)
        handler._send(status, {**result, "request_id": handler._request_id})
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

# 状态类过滤参数必须落在"平台真能判定"的取值内。以前 activation_state 恒为
# unknown，任何取值都只会静默返回全量或空集；现在它有真实取值，非法值必须报错，
# 否则调用方会把"拼错的状态名"读成"没有这类资产"。
# 同理，不能只做白名单校验：broken/idle 虽然写在了 domain 枚举里，但三态推导
# 永远不会产出它们，放进白名单等于给调用方一个永远空结果的合法筛选项——那比
# 报错更糟，因为它读起来像"查过了，没有这类资产"。
STATE_FILTERS = {
    "installation_state": ("unknown", "absent", "installed"),
    "runtime_state": ("unknown", "running", "stopped"),
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
