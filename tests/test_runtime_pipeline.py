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
    # hook_anchor 是绑定元数据，不是被归因对象，所以受评事件是 4 个而不是 5 个。
    assert summary['subject_count']==4 and summary['candidate_count']==4 and summary['selected_count']==3
    # "连不上"和"不敢连"必须分开：background 无任何候选，weak 有候选但不够强。
    assert summary['no_candidate_count']==1 and summary['ambiguous_count']==1
    assert summary['unattributed_count']==2
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


def test_audit_rotation_loses_nothing_across_polls(tmp_path):
    """轮转后两个文件的事件都要采到，但顺序改为"主文件优先"。

    原断言要求"一次采集先把旧文件尾巴读掉"，实测这样会让当前事件滞后十几小时
    （旧文件积压 8MB，每次只读 1MB，主文件要等很多轮）。改为实时优先后：
    第一次读主文件，第二次补旧文件尾巴，总数不变——不丢数据这条保证仍然成立。
    """
    source=tmp_path/'audit.log';first=TRACE.split('type=SYSCALL msg=audit(1794398400.124:11)')[0]
    source.write_text(first)
    cfg={'state_dir':str(tmp_path/'state'),'audit_log':str(source),'audit_uid':1000,'audit_keys':['asgp_p2_exec','asgp_p2_net','asgp_p2_file']}
    assert collect_once(cfg,settled=True)['events']==1
    with source.open('a') as f:f.write(TRACE[len(first):])
    source.rename(tmp_path/'audit.log.1')
    source.write_text(first.replace(':10)',':20)'))
    # 实时优先：这一轮先读主文件里的新事件（1 条）
    assert collect_once(cfg,settled=True)['events']==1
    # 主文件读完，回去补旧文件未读的尾巴（这里是 2 条）
    assert collect_once(cfg,settled=True)['events']==2
    assert collect_once(cfg,settled=True)['events']==0
    box=Outbox(cfg['state_dir'])
    assert box.db.execute('SELECT count(*) FROM outbox').fetchone()[0]==4


def test_collector_excludes_short_lived_hook_and_prevents_spoofing(tmp_path):
    hook_cmd_hex='cd /lab/source && ASGP_ENDPOINT_CONFIG=/lab/endpoint/config.json /usr/bin/python3 -m endpoint.hook qwen-code'.encode().hex()
    spoof_hex='curl example.com # -m endpoint.hook'.encode().hex()
    chain_hex='cd /tmp && cat /lab/.env.secret && /usr/bin/python3 -m endpoint.hook'.encode().hex()
    log_text=f'''type=SYSCALL msg=audit(1794564246.235:4829): arch=c000003e syscall=59 success=no exit=-2 ppid=4676 pid=4692 uid=1000 exe="/lab/bin/node" key="asgp_p2_exec"
type=PROCTITLE msg=audit(1794564246.235:4829): proctitle=6e6f6465
type=EOE msg=audit(1794564246.235:4829):
type=SYSCALL msg=audit(1794564246.235:4831): arch=c000003e syscall=59 success=yes exit=0 ppid=4676 pid=4692 uid=1000 exe="/usr/bin/bash" key="asgp_p2_exec"
type=EXECVE msg=audit(1794564246.235:4831): argc=3 a0="bash" a1="-c" a2={hook_cmd_hex}
type=EOE msg=audit(1794564246.235:4831):
type=SYSCALL msg=audit(1794564246.235:4832): arch=c000003e syscall=59 success=yes exit=0 ppid=4676 pid=4692 uid=1000 exe="/usr/bin/python3.10" key="asgp_p2_exec"
type=EXECVE msg=audit(1794564246.235:4832): argc=4 a0="/usr/bin/python3" a1="-m" a2="endpoint.hook" a3="qwen-code"
type=EOE msg=audit(1794564246.235:4832):
type=SYSCALL msg=audit(1794564246.240:4833): arch=c000003e syscall=257 success=yes exit=3 ppid=4676 pid=4692 uid=1000 exe="/usr/bin/python3.10" key="asgp_p2_file"
type=PATH msg=audit(1794564246.240:4833): item=0 name="/lab/endpoint/outbox.sqlite" nametype=NORMAL
type=EOE msg=audit(1794564246.240:4833):
type=SYSCALL msg=audit(1794564246.300:4834): arch=c000003e syscall=59 success=yes exit=0 ppid=4676 pid=4700 uid=1000 exe="/usr/bin/python3.10" key="asgp_p2_exec"
type=EXECVE msg=audit(1794564246.300:4834): argc=4 a0="/usr/bin/python3" a1="/tmp/evil.py" a2="-m" a3="endpoint.hook"
type=EOE msg=audit(1794564246.300:4834):
type=SYSCALL msg=audit(1794564246.310:4835): arch=c000003e syscall=59 success=yes exit=0 ppid=4676 pid=4701 uid=1000 exe="/usr/bin/bash" key="asgp_p2_exec"
type=EXECVE msg=audit(1794564246.310:4835): argc=3 a0="bash" a1="-c" a2={spoof_hex}
type=EOE msg=audit(1794564246.310:4835):
type=SYSCALL msg=audit(1794564246.320:4836): arch=c000003e syscall=59 success=yes exit=0 ppid=4676 pid=4702 uid=1000 exe="/usr/bin/bash" key="asgp_p2_exec"
type=EXECVE msg=audit(1794564246.320:4836): argc=3 a0="bash" a1="-c" a2={chain_hex}
type=EOE msg=audit(1794564246.320:4836):
'''
    source=tmp_path/'audit.log';source.write_text(log_text)
    cfg={'state_dir':str(tmp_path/'state'),'audit_log':str(source),'audit_uid':1000,'audit_keys':['asgp_p2_exec','asgp_p2_file']}
    res=collect_once(cfg,settled=True)
    assert res['own_telemetry_excluded']==4 and res['events']==3
    box=Outbox(cfg['state_dir'])
    pids=[json.loads(r[0])['events'][0]['process']['pid'] for r in box.db.execute('SELECT payload FROM outbox')]
    assert pids==[4700,4701,4702]
    assert 'evil.py' not in box.db.execute('SELECT payload FROM outbox').fetchone()[0]


def test_closed_call_window_excludes_pre_hook_and_post_turn_helper(tmp_path):
    storage=Storage(tmp_path/'control.db');devices=DeviceIdentityRepository(storage)
    did,_=devices.enroll(label='lab');devices.set_host(device_id=did,host_id='h');ingest=IngestionService(storage)
    base=datetime(2026,11,13,10,4,6,0,tzinfo=timezone.utc)
    def at(ms):return (base+timedelta(milliseconds=ms)).isoformat()
    ingest.execution(did,{'execution_id':'exec_win','session_id':'s','product':'qwen-code','product_version':'0.26.8','started_at':at(0)})
    ingest.intent(did,'exec_win',{'intent_id':'i_read','tool_call_id':'tc_read','tool_name':'read_file','hook_event_type':'pre_tool_use','occurred_at':at(283),'ended_at':at(407)})
    ingest.batch(did,{'collector_id':'test','events':[
        {'event_id':'anchor_r','execution_id':'exec_win','intent_ref':'i_read','event_type':'hook_anchor','occurred_at':at(283),'process':{'pid':4676,'ppid':4675}},
        {'event_id':'pre_hook','event_type':'process_start','occurred_at':at(235),'process':{'pid':4692,'ppid':4676,'executable':'/usr/bin/bash'}},
        {'event_id':'real_read','event_type':'file_access','occurred_at':at(347),'process':{'pid':4676,'ppid':4675},'resource':{'path':'/lab/health_check.sh'}},
        {'event_id':'post_git','event_type':'process_start','occurred_at':at(451),'process':{'pid':4694,'ppid':4676,'executable':'/usr/bin/git'}},
    ]})
    service=AttributionService(storage);service.correlate('exec_win')
    selected={e['event_id'] for e in service.list('exec_win') if e['selected']}
    assert selected=={'anchor_r','real_read'}


def test_collector_skips_local_unix_sockets_and_resolved_path_probes(tmp_path):
    unix_hex='01002f72756e2f646275732f73797374656d5f6275735f736f636b657400'
    inet_hex='020001BB7F0000010000000000000000'
    log_text=f'''type=SYSCALL msg=audit(1794569607.567:6630): arch=c000003e syscall=59 success=no exit=-2 ppid=6712 pid=6731 uid=1000 exe="/lab/bin/node" key="asgp_p2_exec"
type=EOE msg=audit(1794569607.567:6630):
type=SYSCALL msg=audit(1794569607.567:6631): arch=c000003e syscall=59 success=yes exit=0 ppid=6712 pid=6731 uid=1000 exe="/usr/bin/systemd-inhibit" key="asgp_p2_exec"
type=EOE msg=audit(1794569607.567:6631):
type=SYSCALL msg=audit(1794569607.571:6633): arch=c000003e syscall=42 success=yes exit=0 ppid=6712 pid=6731 uid=1000 exe="/usr/bin/systemd-inhibit" key="asgp_p2_net"
type=SOCKADDR msg=audit(1794569607.571:6633): saddr={unix_hex}
type=EOE msg=audit(1794569607.571:6633):
type=SYSCALL msg=audit(1794569607.575:6634): arch=c000003e syscall=42 success=yes exit=0 ppid=6712 pid=6732 uid=1000 exe="/usr/bin/curl" key="asgp_p2_net"
type=SOCKADDR msg=audit(1794569607.575:6634): saddr={inet_hex}
type=EOE msg=audit(1794569607.575:6634):
'''
    source=tmp_path/'audit.log';source.write_text(log_text)
    cfg={'state_dir':str(tmp_path/'state'),'audit_log':str(source),'audit_uid':1000,'audit_keys':['asgp_p2_exec','asgp_p2_net']}
    res=collect_once(cfg,settled=True)
    assert res['events']==2 and res['own_telemetry_excluded']==0
    box=Outbox(cfg['state_dir'])
    items=[json.loads(r[0])['events'][0] for r in box.db.execute('SELECT payload FROM outbox ORDER BY rowid')]
    assert [(i['event_type'],i['process']['executable']) for i in items]==[
        ('process_start','/usr/bin/systemd-inhibit'),
        ('network_connect','/usr/bin/curl'),
    ]



def test_correlate_prunes_stale_edges_and_skips_deny_open_window(tmp_path):
    storage=Storage(tmp_path/'control.db');devices=DeviceIdentityRepository(storage)
    did,_=devices.enroll(label='lab');devices.set_host(device_id=did,host_id='h');ingest=IngestionService(storage)
    base=datetime(2026,11,13,10,4,6,0,tzinfo=timezone.utc)
    def at(ms):return (base+timedelta(milliseconds=ms)).isoformat()
    ingest.execution(did,{'execution_id':'exec_pr','session_id':'s1','product':'qwen-code','product_version':'0.26.8','started_at':at(0)})
    ingest.intent(did,'exec_pr',{'intent_id':'i_read','tool_call_id':'tc_read','tool_name':'read_file','hook_event_type':'pre_tool_use','occurred_at':at(283)})
    ingest.batch(did,{'collector_id':'test','events':[
        {'event_id':'anchor_r','execution_id':'exec_pr','intent_ref':'i_read','event_type':'hook_anchor','occurred_at':at(283),'process':{'pid':4676,'ppid':4675}},
        {'event_id':'pre_hook','event_type':'process_start','occurred_at':at(235),'process':{'pid':4692,'ppid':4676,'executable':'/usr/bin/bash'}},
        {'event_id':'real_read','event_type':'file_access','occurred_at':at(347),'process':{'pid':4676,'ppid':4675},'resource':{'path':'/lab/health_check.sh'}},
        {'event_id':'post_git','event_type':'process_start','occurred_at':at(451),'process':{'pid':4694,'ppid':4676,'executable':'/usr/bin/git'}},
    ]})
    service=AttributionService(storage)
    # First correlate before PostToolUse sets ended_at: wide window captures post_git & pre_hook
    service.correlate('exec_pr')
    assert {e['event_id'] for e in service.list('exec_pr') if e['selected']}=={'anchor_r','pre_hook','real_read','post_git'}
    # Now PostToolUse closes ended_at and re-correlate must prune stale pre/post edges
    ingest.intent(did,'exec_pr',{'intent_id':'i_read','tool_call_id':'tc_read','tool_name':'read_file','hook_event_type':'post_tool_use','occurred_at':at(283),'ended_at':at(407)})
    service.correlate('exec_pr')
    assert {e['event_id'] for e in service.list('exec_pr') if e['selected']}=={'anchor_r','real_read'}

    # Denied intent without PostToolUse must not absorb +30s unrelated events
    ingest.execution(did,{'execution_id':'exec_deny','session_id':'s2','product':'codex','product_version':'0.166.0','started_at':at(1000)})
    ingest.intent(did,'exec_deny',{'intent_id':'i_deny','tool_call_id':'tc_deny','tool_name':'Bash','hook_event_type':'pre_tool_use','decision':'deny','decision_reason':'policy','occurred_at':at(1200)})
    ingest.batch(did,{'collector_id':'test','events':[
        {'event_id':'anchor_d','execution_id':'exec_deny','intent_ref':'i_deny','event_type':'hook_anchor','occurred_at':at(1200),'process':{'pid':5000,'ppid':1}},
        {'event_id':'ambient_net','event_type':'network_connect','occurred_at':at(1230),'process':{'pid':5001,'ppid':5000,'executable':'/usr/bin/python3'},'resource':{'host':'127.0.0.1','port':18082}},
    ]})
    service.correlate('exec_deny')
    assert {e['event_id'] for e in service.list('exec_deny') if e['selected']}=={'anchor_d'}
