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
    assert first['attribution_supported'] is True
    assert 'attribution' in first['sections_supported']
    assert 'finding' in first['sections_pending']
    second=call(api.base,'GET',url+'&cursor='+first['next_cursor'],token=admin_token).json()
    assert [r['id'] for r in first['entries']+second['entries']]==['i0','i1','i2']
    assert second['next_cursor'] is None
    assert call(api.base,'GET',url+'&cursor=bogus',token=admin_token).status_code==400
    assert call(api.base,'GET','/api/v1/executions/missing/timeline',token=admin_token).status_code==404
    # Execution IDs cannot be reassigned to another session even by same device.
    assert call(api.base,'POST','/api/v1/executions',token=dev['token'],body=dict(data,session_id='different')).status_code==409


def test_correlated_unassociated_runtime_event_appears_with_candidate_edges(api,admin_token):
    dev=setup_device(api,admin_token);data=execution()
    call(api.base,'POST','/api/v1/executions',token=dev['token'],body=data).raise_for_status()
    call(api.base,'POST','/api/v1/executions/exec_1/intents',token=dev['token'],body={
        'intent_id':'i','tool_name':'Bash','tool_call_id':'call','hook_event_type':'pre_tool_use','occurred_at':data['started_at']}).raise_for_status()
    call(api.base,'POST','/api/v1/runtime-events:batch',token=dev['token'],body={'collector_id':'test','events':[
        {'event_id':'anchor','event_type':'hook_anchor','execution_id':'exec_1','intent_ref':'i','occurred_at':data['started_at'],'process':{'pid':100,'ppid':1}},
        {'event_id':'child','event_type':'process_start','occurred_at':data['started_at'],'process':{'pid':101,'ppid':100}}
    ]}).raise_for_status()
    call(api.base,'POST','/api/v1/executions/exec_1/correlate',token=admin_token,body={}).raise_for_status()
    result=call(api.base,'GET','/api/v1/executions/exec_1/timeline',token=admin_token).json()
    assert len(result['attributions'])==2 and len(result['entries'])==3
    child=next(e for e in result['entries'] if e['id']=='test:child')
    assert child['data']['execution_id'] is None
    assert child['data']['attributions'][0]['method']=='process_tree'
