"""Audit 解析/持久游标、崩溃重放以及有标注归因轨迹。"""
import json
from pathlib import Path
from datetime import datetime,timezone,timedelta
from endpoint.audit import record,normalize,collect_once
from endpoint.outbox import Outbox
from services.attribution_service import AttributionService
from storage.repositories import Storage,DeviceIdentityRepository
from services.ingestion_service import IngestionService

TRACE='''type=SYSCALL msg=audit(1794398400.123:10): arch=c000003e syscall=59 success=yes exit=0 ppid=100 pid=101 uid=1000 exe="/usr/bin/printf" key="asgp_p2_exec"
type=EXECVE msg=audit(1794398400.123:10): argc=2 a0="printf" a1="PRIVATE_SECRET_MUST_NOT_UPLOAD"
type=PROCTITLE msg=audit(1794398400.123:10): proctitle=70726976617465
type=EOE msg=audit(1794398400.123:10):
type=SYSCALL msg=audit(1794398400.124:11): arch=c000003e syscall=42 success=yes exit=0 ppid=101 pid=102 uid=1000 exe="/usr/bin/python3" key="asgp_p2_net"
type=SOCKADDR msg=audit(1794398400.124:11): saddr=020001BB7F0000010000000000000000
type=EOE msg=audit(1794398400.124:11):
type=SYSCALL msg=audit(1794398400.125:12): arch=c000003e syscall=257 success=yes exit=3 ppid=101 pid=102 uid=1000 exe="/usr/bin/python3" key="asgp_p2_file"
type=PATH msg=audit(1794398400.125:12): item=0 name="/lab/proof.txt" nametype=NORMAL
type=EOE msg=audit(1794398400.125:12):
'''


def test_audit_uid_scope_ipv4_file_and_no_arguments():
    grouped={}
    for line in TRACE.splitlines():
        row=record(line)
        grouped.setdefault(row[:2],[]).append(row)
    events=[]
    for rows in grouped.values():events.extend(normalize(rows,uid=1000,keys={'asgp_p2_exec','asgp_p2_net','asgp_p2_file'},boot_id='boot'))
    assert [e['event_type'] for e in events]==['process_start','network_connect','file_access']
    assert events[1]['resource']=={'host':'127.0.0.1','port':443}
    assert events[2]['resource']['path']=='/lab/proof.txt'
    assert 'PRIVATE_SECRET' not in json.dumps(events) and 'proctitle' not in json.dumps(events)
    assert normalize(list(grouped.values())[0],uid=999,keys={'asgp_p2_exec'},boot_id='boot')==[]
    assert normalize(list(grouped.values())[0],uid=1000,keys={'other'},boot_id='boot')==[]


def test_cursor_atomic_queue_restart_replay_and_partial_line(tmp_path):
    source=tmp_path/'audit.log';source.write_text(TRACE)
    cfg={'state_dir':str(tmp_path/'state'),'audit_log':str(source),'audit_uid':1000,'audit_keys':['asgp_p2_exec','asgp_p2_net','asgp_p2_file']}
    result=collect_once(cfg,settled=True);assert result['events']==3
    assert collect_once(cfg,settled=True)['events']==0
    box=Outbox(cfg['state_dir'])
    with box.db:box.db.execute('UPDATE collector_cursors SET offset=0')
    box.close()
    assert collect_once(cfg,settled=True)['events']==3
    box=Outbox(cfg['state_dir']);assert box.db.execute('SELECT count(*) FROM outbox').fetchone()[0]==3
    box.close()
    with source.open('a') as f:f.write('type=SYSCALL msg=audit(1794398401.123:13): arch=c000003e syscall=59')
    try:collect_once(cfg,settled=True)
    except ValueError:pass
    box=Outbox(cfg['state_dir']);assert box.db.execute('select offset from collector_cursors').fetchone()[0]==len(TRACE.encode())


def test_labeled_attribution_exact_tree_weak_and_unattributed(tmp_path):
    storage=Storage(tmp_path/'control.db');devices=DeviceIdentityRepository(storage)
    did,token=devices.enroll(label='lab');devices.set_host(device_id=did,host_id='h')
    ingest=IngestionService(storage);stamp='2026-11-11T12:00:00+00:00'
    ingest.execution(did,{'execution_id':'exec','session_id':'s','product':'codex','product_version':'0.166.0','started_at':stamp})
    ingest.intent(did,'exec',{'intent_id':'i1','tool_call_id':'call1','tool_name':'Bash','hook_event_type':'pre_tool_use','occurred_at':stamp,'params_summary':json.dumps({'resource_hint':'/lab/proof'})})
    ingest.intent(did,'exec',{'intent_id':'i2','tool_call_id':'call2','tool_name':'Read','hook_event_type':'pre_tool_use','occurred_at':stamp,'params_summary':json.dumps({'resource_hint':'/lab/weak'})})
    items=[{'event_id':'anchor','execution_id':'exec','intent_ref':'i1','event_type':'hook_anchor','occurred_at':stamp,'process':{'pid':100,'ppid':1}},
       {'event_id':'process','event_type':'process_start','occurred_at':stamp,'process':{'pid':101,'ppid':100}},
       {'event_id':'network','event_type':'network_connect','occurred_at':stamp,'process':{'pid':101,'ppid':100},'resource':{'host':'127.0.0.1','port':443}},
       {'event_id':'weak','event_type':'file_access','occurred_at':stamp,'process':{'pid':999,'ppid':1},'resource':{'path':'/lab/weak'}},
       {'event_id':'background','event_type':'process_start','occurred_at':stamp,'process':{'pid':900,'ppid':1}}]
    ingest.batch(did,{'collector_id':'test','events':items})
    service=AttributionService(storage);summary=service.correlate('exec');edges=service.list('exec')
    assert summary['candidate_count']==4 and summary['selected_count']==3 and summary['unattributed_count']==1
    selected={e['event_id']:e['intent_id'] for e in edges if e['selected']}
    truth={'anchor':'i1','process':'i1','network':'i1'}
    tp=sum(selected.get(k)==v for k,v in truth.items());fp=sum(k not in truth or truth[k]!=v for k,v in selected.items())
    precision=tp/(tp+fp);recall=tp/len(truth)
    assert precision==recall==1
    assert next(e for e in edges if e['event_id']=='weak')['selected'] is False
    assert not any(e['event_id']=='background' for e in edges)
    assert all(e['rule_version'] and e['evidence_refs'] for e in edges)
    service.correlate('exec');assert len(service.list('exec'))==4


def test_overlapping_calls_do_not_force_single_causal_choice(tmp_path):
    storage=Storage(tmp_path/'control.db');devices=DeviceIdentityRepository(storage)
    did,_=devices.enroll(label='lab');devices.set_host(device_id=did,host_id='h');ingest=IngestionService(storage)
    stamp='2026-11-11T12:00:00+00:00'
    ingest.execution(did,{'execution_id':'exec','session_id':'s','product':'codex','product_version':'0.166.0','started_at':stamp})
    for i in ['a','b']:
        ingest.intent(did,'exec',{'intent_id':i,'tool_call_id':i,'tool_name':'Bash','hook_event_type':'pre_tool_use','occurred_at':stamp})
    ingest.batch(did,{'collector_id':'test','events':[{'event_id':'anchor_'+i,'execution_id':'exec','intent_ref':i,'event_type':'hook_anchor','occurred_at':stamp,'process':{'pid':100,'ppid':1}} for i in ['a','b']]+[{'event_id':'child','event_type':'process_start','occurred_at':stamp,'process':{'pid':101,'ppid':100}}]})
    service=AttributionService(storage);service.correlate('exec');edges=[e for e in service.list('exec') if e['event_id']=='child']
    assert len(edges)==2 and not any(e['selected'] for e in edges)


def test_collector_excludes_its_reporter_feedback_without_advancing_on_full_queue(tmp_path,monkeypatch):
    import endpoint.audit as audit
    source=tmp_path/'audit.log';source.write_text(TRACE)
    cfg={'state_dir':str(tmp_path/'state'),'audit_log':str(source),'audit_uid':1000,'audit_keys':['asgp_p2_exec','asgp_p2_net','asgp_p2_file'],'max_records':1}
    # All three records are our reporter: checkpoint them, enqueue none.
    monkeypatch.setattr(audit,'is_own_telemetry_pid',lambda pid:True)
    assert collect_once(cfg,settled=True)['events']==0
    box=Outbox(cfg['state_dir']);assert box.db.execute('SELECT count(*) FROM outbox').fetchone()[0]==0
    with box.db:box.db.execute('UPDATE collector_cursors SET offset=0')
    box.close()
    monkeypatch.setattr(audit,'is_own_telemetry_pid',lambda pid:False)
    import pytest
    with pytest.raises(RuntimeError,match='capacity'):collect_once(cfg,settled=True)
    box=Outbox(cfg['state_dir'])
    assert box.db.execute('SELECT offset FROM collector_cursors').fetchone()[0]==0
    assert box.db.execute('SELECT count(*) FROM outbox').fetchone()[0]==0


def test_new_conflicting_evidence_demotes_previously_selected_edge(tmp_path):
    storage=Storage(tmp_path/'control.db');devices=DeviceIdentityRepository(storage)
    did,_=devices.enroll(label='lab');devices.set_host(device_id=did,host_id='h');ingest=IngestionService(storage)
    stamp='2026-11-11T12:00:00+00:00'
    ingest.execution(did,{'execution_id':'exec','session_id':'s','product':'codex','product_version':'0.166.0','started_at':stamp})
    ingest.intent(did,'exec',{'intent_id':'a','tool_call_id':'a','tool_name':'Bash','hook_event_type':'pre_tool_use','occurred_at':stamp})
    ingest.batch(did,{'collector_id':'test','events':[{'event_id':'anchor_a','execution_id':'exec','intent_ref':'a','event_type':'hook_anchor','occurred_at':stamp,'process':{'pid':100,'ppid':1}},{'event_id':'child','event_type':'process_start','occurred_at':stamp,'process':{'pid':101,'ppid':100}}]})
    service=AttributionService(storage);service.correlate('exec')
    assert next(e for e in service.list('exec') if e['event_id']=='child')['selected']
    ingest.intent(did,'exec',{'intent_id':'b','tool_call_id':'b','tool_name':'Bash','hook_event_type':'pre_tool_use','occurred_at':stamp})
    ingest.batch(did,{'collector_id':'test','events':[{'event_id':'anchor_b','execution_id':'exec','intent_ref':'b','event_type':'hook_anchor','occurred_at':stamp,'process':{'pid':100,'ppid':1}}]})
    service.correlate('exec')
    edges=[e for e in service.list('exec') if e['event_id']=='child']
    assert len(edges)==2 and all(not e['selected'] for e in edges)


def test_audit_rotation_drains_original_inode_before_new_file(tmp_path):
    source=tmp_path/'audit.log';first=TRACE.split('type=SYSCALL msg=audit(1794398400.124:11)')[0]
    source.write_text(first)
    cfg={'state_dir':str(tmp_path/'state'),'audit_log':str(source),'audit_uid':1000,'audit_keys':['asgp_p2_exec','asgp_p2_net','asgp_p2_file']}
    assert collect_once(cfg,settled=True)['events']==1
    with source.open('a') as f:f.write(TRACE[len(first):])
    source.rename(tmp_path/'audit.log.1')
    source.write_text(first.replace(':10)',':20)'))
    assert collect_once(cfg,settled=True)['events']==2
    assert collect_once(cfg,settled=True)['events']==1
    assert collect_once(cfg,settled=True)['events']==0
    box=Outbox(cfg['state_dir'])
    assert box.db.execute('SELECT count(*) FROM outbox').fetchone()[0]==4
