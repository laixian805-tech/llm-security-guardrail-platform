"""真实 HTTP 设备鉴权、跨设备隔离和秘密拒收。"""
import json
from datetime import datetime, timezone
import pytest
from test_console_auth import api, admin_token, call


def setup_device(api, admin_token, label='lab'):
    response=call(api.base,'POST','/api/devices',token=admin_token,body={'label':label})
    result=response.json()
    call(api.base,'PATCH','/api/devices/'+result['device_id'],token=admin_token,body={'host_id':'host_'+label}).raise_for_status()
    return result


def execution(identifier='exec_1'):
    return {'execution_id':identifier,'session_id':'sess_'+identifier,'product':'codex','product_version':'0.166.0',
            'started_at':datetime.now(timezone.utc).isoformat(),'host_id':'forged','device_id':'forged'}


def test_device_auth_host_override_rotation_and_revocation(api,admin_token):
    dev=setup_device(api,admin_token)
    url='/api/v1/executions'; body=execution()
    assert call(api.base,'POST',url,body=body).status_code==401
    assert call(api.base,'POST',url,token=admin_token,body=body).status_code==401
    r=call(api.base,'POST',url,token=dev['token'],body=body)
    assert r.status_code==200,r.text
    assert call(api.base,'GET','/api/summary',token=dev['token']).status_code==401
    rows=call(api.base,'GET',url,token=admin_token).json()['executions']
    assert rows[0]['host_id']=='host_lab' and rows[0]['device_id']==dev['device_id']
    assert call(api.base,'POST',url,token=dev['token'],body=body).json()['duplicate'] is True
    rotated=call(api.base,'POST','/api/devices/'+dev['device_id']+'/rotate-token',token=admin_token,body={}).json()['token']
    assert call(api.base,'POST',url,token=dev['token'],body=body).status_code==401
    assert call(api.base,'POST',url,token=rotated,body=body).status_code==200
    call(api.base,'PATCH','/api/devices/'+dev['device_id'],token=admin_token,body={'status':'revoked'}).raise_for_status()
    assert call(api.base,'POST',url,token=rotated,body=body).status_code==403
    audit=call(api.base,'GET','/api/audit?actor_kind=device',token=admin_token)
    assert dev['device_id'] in audit.text
    assert dev['token'] not in audit.text and rotated not in audit.text


def test_cross_device_intent_and_event_cannot_attach_to_another_execution(api,admin_token):
    a=setup_device(api,admin_token,'a');b=setup_device(api,admin_token,'b')
    call(api.base,'POST','/api/v1/executions',token=a['token'],body=execution()).raise_for_status()
    assert call(api.base,'POST','/api/v1/executions',token=b['token'],body=execution()).status_code==409
    intent={'intent_id':'i1','tool_name':'exec_command','tool_call_id':'c1','hook_event_type':'pre_tool_use','occurred_at':execution()['started_at']}
    assert call(api.base,'POST','/api/v1/executions/exec_1/intents',token=b['token'],body=intent).status_code==409
    batch={'collector_id':'codex-hook-v1','events':[{'event_id':'e1','execution_id':'exec_1','event_type':'observed','occurred_at':execution()['started_at']}]}
    assert call(api.base,'POST','/api/v1/runtime-events:batch',token=b['token'],body=batch).status_code==409
    call(api.base,'POST','/api/v1/runtime-events:batch',token=a['token'],body=batch).raise_for_status()
    assert call(api.base,'POST','/api/v1/runtime-events:batch',token=a['token'],body=batch).json()['duplicates']==1
    invalid={'collector_id':'codex-hook-v1','events':[dict(batch['events'][0],event_id='e2'),dict(batch['events'][0],event_id='e3',unexpected='x')]}
    assert call(api.base,'POST','/api/v1/runtime-events:batch',token=a['token'],body=invalid).status_code==400
    with api.module.storage.connection() as conn:
        assert conn.execute('SELECT count(*) FROM runtime_events').fetchone()[0]==1


@pytest.mark.parametrize('injected',[{'prompt':'private prompt text'}, {'tool_input':{'password':'private'}}, {'session_id':'sk-ant-'+'a'*30}])
def test_secrets_rejected_without_echo_or_audit_leak(api,admin_token,injected):
    dev=setup_device(api,admin_token)
    body={**execution(),**injected}
    r=call(api.base,'POST','/api/v1/executions',token=dev['token'],body=body)
    assert r.status_code==400
    assert 'suspected_secret_parameter' in r.text
    audit=call(api.base,'GET','/api/audit',token=admin_token).text
    assert 'private prompt text' not in r.text+audit
    assert 'sk-ant-'+'a'*30 not in r.text+audit


def test_host_binding_is_immutable_and_unbound_fails(api,admin_token,monkeypatch):
    dev=call(api.base,'POST','/api/devices',token=admin_token,body={'label':'unbound'}).json()
    r=call(api.base,'POST','/api/v1/executions',token=dev['token'],body=execution())
    assert r.status_code==409 and 'host_unbound' in r.text
    call(api.base,'PATCH','/api/devices/'+dev['device_id'],token=admin_token,body={'host_id':'original'}).raise_for_status()
    assert call(api.base,'PATCH','/api/devices/'+dev['device_id'],token=admin_token,body={'host_id':'changed'}).status_code==400
    monkeypatch.setenv('ASGP_V1_ENABLED','0')
    assert call(api.base,'GET','/api/v1/executions',token=admin_token).status_code==503
    assert call(api.base,'GET','/api/summary',token=admin_token).status_code==200


def test_codex_cannot_claim_unsupported_confirmation(api,admin_token):
    dev=setup_device(api,admin_token)
    data=execution()
    call(api.base,'POST','/api/v1/executions',token=dev['token'],body=data).raise_for_status()
    intent={'intent_id':'ask1','tool_name':'Bash','tool_call_id':'c1','hook_event_type':'pre_tool_use',
        'decision':'ask','decision_reason':'test','occurred_at':data['started_at']}
    r=call(api.base,'POST','/api/v1/executions/exec_1/intents',token=dev['token'],body=intent)
    assert r.status_code==400 and 'unsupported_decision' in r.text
