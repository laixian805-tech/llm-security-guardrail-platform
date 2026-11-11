from test_console_auth import api, admin_token, call
from test_v1_ingest import setup_device, execution


def test_timeline_equal_timestamp_cursor_and_identity_conflict(api,admin_token):
    dev=setup_device(api,admin_token)
    data=execution()
    call(api.base,'POST','/api/v1/executions',token=dev['token'],body=data).raise_for_status()
    for i in range(3):
        intent={'intent_id':'i'+str(i),'tool_name':'Bash','tool_call_id':'c'+str(i),
                'hook_event_type':'pre_tool_use','occurred_at':data['started_at']}
        call(api.base,'POST','/api/v1/executions/exec_1/intents',token=dev['token'],body=intent).raise_for_status()
    url='/api/v1/executions/exec_1/timeline?limit=2'
    assert call(api.base,'GET',url).status_code==401
    first=call(api.base,'GET',url,token=admin_token).json()
    assert first['attribution_supported'] is False
    assert 'attribution' in first['sections_pending']
    second=call(api.base,'GET',url+'&cursor='+first['next_cursor'],token=admin_token).json()
    assert [r['id'] for r in first['entries']+second['entries']]==['i0','i1','i2']
    assert second['next_cursor'] is None
    assert call(api.base,'GET',url+'&cursor=bogus',token=admin_token).status_code==400
    assert call(api.base,'GET','/api/v1/executions/missing/timeline',token=admin_token).status_code==404
    # Execution IDs cannot be reassigned to another session even by same device.
    assert call(api.base,'POST','/api/v1/executions',token=dev['token'],body=dict(data,session_id='different')).status_code==409
