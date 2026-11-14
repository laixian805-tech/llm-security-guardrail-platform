"""ASGP 调用审批；仅显式启用时同步等待，失败/超时一律拒绝。

普通 observe 路径不触网。请求只含设备身份绑定的调用标识、工具名和完整
参数的摘要哈希；凭据仅在 Authorization 头，禁止重定向。
"""
import hashlib
import json
import time
import urllib.request
from datetime import datetime,timezone


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None


def request_approval(config,product,version,event):
    timeout=min(max(int(config.get('approval_timeout_seconds',15)),1),20)
    if not event['tool_call_id']:
        return 'deny','ASGP approval requires a stable tool call ID'
    digest=hashlib.sha256(json.dumps(event['params'],ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    body={'product':product,'product_version':version,'session_id':event['session_id'],
        'tool_call_id':event['tool_call_id'],'tool_name':event['tool_name'],'params_sha256':digest,'timeout_seconds':timeout}
    base=config['server_base_url'].rstrip('/')
    opener=urllib.request.build_opener(NoRedirect)
    deadline=time.monotonic()+timeout
    def call(path,payload=None,timeout_cap=2.0):
        request=urllib.request.Request(base+path,data=json.dumps(payload).encode() if payload is not None else None,
            headers={'Authorization':'Bearer '+config['device_token'],'Content-Type':'application/json'})
        remaining=deadline-time.monotonic()
        if remaining<=0:raise TimeoutError
        with opener.open(request,timeout=min(timeout_cap,remaining)) as response:
            return json.loads(response.read(64*1024))
    try:
        result=call('/api/v1/approval-requests',body)
        identifier=result['approval_id']
        while True:
            for field in ['product','product_version','session_id','tool_call_id','tool_name','params_sha256']:
                if result[field]!=body[field]:raise ValueError('approval_binding_mismatch')
            # Python 3.10 does not accept the RFC3339 Z suffix emitted by Pydantic.
            expiry=datetime.fromisoformat(result['expires_at'].replace('Z','+00:00'))
            if expiry.tzinfo is None or expiry<=datetime.now(timezone.utc):
                return 'deny','ASGP approval expired '+identifier
            if result['state']=='approved':return 'allow','ASGP operator approved '+identifier
            if result['state']!='pending':return 'deny','ASGP operator denied or expired '+identifier
            if time.monotonic()>=deadline:return 'deny','ASGP approval timeout '+identifier
            remaining=deadline-time.monotonic()
            if remaining<=0:return 'deny','ASGP approval timeout '+identifier
            if config.get('approval_push_wait', True) and remaining>0.4:
                wait_sec=round(min(1.5,max(0.2,remaining-0.3)),2)
                t0=time.monotonic()
                result=call('/api/v1/approval-requests/'+identifier+'?wait=1&timeout='+str(wait_sec),timeout_cap=wait_sec+1.0)
                if result['state']=='pending' and (time.monotonic()-t0)<0.15:
                    time.sleep(min(.2,max(0,deadline-time.monotonic())))
            else:
                time.sleep(min(.2,max(0,remaining)))
                result=call('/api/v1/approval-requests/'+identifier)
    except Exception:
        return 'deny','ASGP approval unavailable or invalid'
