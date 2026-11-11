"""P1 路由：与既有控制台 API 共用 HTTP 服务，设备凭据独立校验。"""
import re
from urllib.parse import parse_qs, unquote
from services.ingestion_service import IngestError

EXECUTION = re.compile(r"^/api/v1/executions/([^/]+)/(intents|timeline)$")


def is_device_route(method, path):
    if path == '/api/v1/approval-requests' and method == 'POST':
        return True
    if path.startswith('/api/v1/approval-requests/') and method == 'GET':
        return True
    match = EXECUTION.fullmatch(path)
    return method == "POST" and (path in ("/api/v1/executions", "/api/v1/runtime-events:batch")
        or bool(match and match[2] == "intents"))


def route(handler, method, parsed, ingestion, timeline):
    path = parsed.path
    match = EXECUTION.fullmatch(path)
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
