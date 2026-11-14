"""审批必须绑定设备、调用、参数；拒绝/过期不能重写成批准。"""
import hashlib,json,threading,time
import pytest
from test_console_auth import api,admin_token,call
from test_v1_ingest import setup_device
from endpoint.approval import request_approval


def body():
    return {'product':'codex','product_version':'0.166.0','session_id':'s','tool_call_id':'call','tool_name':'Bash','params_sha256':'a'*64,'timeout_seconds':10}


def test_approval_auth_binding_expiry_and_operator_only(api,admin_token):
    a=setup_device(api,admin_token,'a');b=setup_device(api,admin_token,'b')
    assert call(api.base,'POST','/api/v1/approval-requests',token=admin_token,body=body()).status_code==401
    request=call(api.base,'POST','/api/v1/approval-requests',token=a['token'],body=body())
    assert request.status_code==200,request.text
    data=request.json();identifier=data['approval_id']
    assert call(api.base,'GET','/api/v1/approval-requests/'+identifier,token=b['token']).status_code==404
    assert call(api.base,'GET','/api/v1/approvals',token=a['token']).status_code==401
    assert call(api.base,'POST','/api/v1/approvals/'+identifier,token=admin_token,body={'decision':'approved','params_sha256':'b'*64}).status_code==409
    r=call(api.base,'POST','/api/v1/approvals/'+identifier,token=admin_token,body={'decision':'denied','params_sha256':'a'*64})
    assert r.status_code==200,r.text
    assert call(api.base,'POST','/api/v1/approvals/'+identifier,token=admin_token,body={'decision':'approved','params_sha256':'a'*64}).status_code==409
    # Same call/digest is idempotent and cannot gain a fresh approval after refusal.
    assert call(api.base,'POST','/api/v1/approval-requests',token=a['token'],body=body()).json()['state']=='denied'
    changed=body();changed['params_sha256']='b'*64
    assert call(api.base,'POST','/api/v1/approval-requests',token=a['token'],body=changed).json()['approval_id']!=identifier
    with api.module.storage.connection() as c:c.execute("UPDATE approval_requests SET state='pending',expires_at='2000-01-01T00:00:00+00:00' WHERE approval_id=?",(identifier,))
    assert call(api.base,'GET','/api/v1/approval-requests/'+identifier,token=a['token']).json()['state']=='expired'


@pytest.mark.parametrize('decision,expected',[('approved','allow'),('denied','deny')])
def test_endpoint_waits_for_bound_console_decision(api,admin_token,tmp_path,decision,expected):
    device=setup_device(api,admin_token)
    config={'server_base_url':api.base,'device_token':device['token'],'approval_timeout_seconds':5}
    event={'session_id':'s','tool_call_id':'t','tool_name':'Bash','params':{'command':'echo PRIVATE_COMMAND'}}
    outcome=[]
    worker=threading.Thread(target=lambda:outcome.append(request_approval(config,'codex','0.166.0',event)));worker.start()
    for _ in range(30):
        rows=call(api.base,'GET','/api/v1/approvals',token=admin_token).json()['approvals']
        if rows:break
        time.sleep(.05)
    assert rows
    row=rows[0]
    assert 'PRIVATE_COMMAND' not in json.dumps(rows)
    assert row['params_sha256']==hashlib.sha256(json.dumps(event['params'],ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    response=call(api.base,'POST','/api/v1/approvals/'+row['approval_id'],token=admin_token,body={'decision':decision,'params_sha256':row['params_sha256']})
    assert response.status_code==200,response.text
    worker.join(timeout=8)
    assert not worker.is_alive() and outcome[0][0]==expected


def test_endpoint_offline_approval_fails_closed():
    config={'server_base_url':'http://127.0.0.1:1','device_token':'fake','approval_timeout_seconds':1}
    event={'session_id':'s','tool_call_id':'t','tool_name':'Bash','params':{}}
    assert request_approval(config,'codex','0.166.0',event)[0]=='deny'
def test_approved_approval_cannot_replay_or_outlive_expiry(api,admin_token):
    device=setup_device(api,admin_token,'replay')
    req=body();req['tool_call_id']='call-replay'
    created=call(api.base,'POST','/api/v1/approval-requests',token=device['token'],body=req)
    assert created.status_code==200,created.text
    identifier=created.json()['approval_id']
    resolved=call(api.base,'POST','/api/v1/approvals/'+identifier,token=admin_token,body={'decision':'approved','params_sha256':req['params_sha256']})
    assert resolved.status_code==200,resolved.text
    # Re-submitting POST /api/v1/approval-requests for an already approved call must be rejected (no replay).
    replayed=call(api.base,'POST','/api/v1/approval-requests',token=device['token'],body=req)
    assert replayed.status_code==409
    assert replayed.json()['error']['code']=='approval_replay_forbidden'
    # Device polling past expires_at sees expired even after approval, while operator console preserves audit state.
    with api.module.storage.connection() as c:
        c.execute("UPDATE approval_requests SET expires_at='2000-01-01T00:00:00+00:00' WHERE approval_id=?",(identifier,))
    assert call(api.base,'GET','/api/v1/approval-requests/'+identifier,token=device['token']).json()['state']=='expired'
    assert call(api.base,'GET','/api/v1/approvals',token=admin_token).json()['approvals'][0]['state']=='approved'
