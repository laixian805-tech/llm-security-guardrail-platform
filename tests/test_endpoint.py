"""端点的真实 SQLite/HTTP 路径，包含重启与重放。"""
import json
import time
from pathlib import Path
import pytest
from endpoint.hook import capture
from endpoint.outbox import Outbox
from endpoint.flush import flush
from endpoint.redaction import redact, summarize
from test_console_auth import api, admin_token, call
from test_v1_ingest import setup_device


def config(tmp_path):
    return {'state_dir':str(tmp_path/'endpoint'),'product_versions':{'codex':'0.166.0','claude-code':'2.1.152'},'fail_mode':'observe'}


def payload(name,product='codex'):
    result={'hook_event_name':name,'session_id':'s1','cwd':'/lab','transcript_path':'/private/transcript'}
    if 'ToolUse' in name:
        result.update(tool_name='exec_command' if product=='codex' else 'Bash',tool_use_id='call_1',tool_input={'command':'echo sk-ant-'+'a'*30,'api_key':'unrecognised-secret'})
    if name=='PostToolUse':result['tool_response']={'stdout':'private output'}
    return result


@pytest.mark.parametrize('product',['codex','claude-code'])
def test_capture_persists_without_prompt_or_parameter_values(tmp_path,product):
    cfg=config(tmp_path)
    for name in ['SessionStart','PreToolUse','PostToolUse','SessionEnd']:
        assert capture(cfg,product,payload(name,product))==''
    box=Outbox(cfg['state_dir'])
    rows=[dict(r) for r in box.db.execute('SELECT * FROM outbox')]
    assert len(rows)==4
    text=json.dumps(rows)
    for forbidden in ['unrecognised-secret','private output','/private/transcript','sk-ant-'+'a'*30]:assert forbidden not in text
    assert all(r['state']=='pending' for r in rows)
    box.close()
    assert len(list(Outbox(cfg['state_dir']).db.execute('SELECT * FROM outbox')))==4


def test_redaction_and_capacity_and_unverified_decision(tmp_path):
    assert redact({'API_KEY':'anything','nested':['Bearer abcdefghijklmnop']})=={'API_KEY':'[密钥已脱敏]','nested':['[密钥已脱敏]']}
    cfg=config(tmp_path);cfg['fail_mode']='deny'
    with pytest.raises(ValueError,match='not_verified'):capture(cfg,'codex',payload('PreToolUse'))
    box=Outbox(tmp_path/'tiny',max_records=1)
    box.enqueue_many([('1','/api',{})])
    with pytest.raises(RuntimeError,match='capacity'):box.enqueue_many([('2','/api',{})])
    assert box.db.execute('select count(*) from outbox').fetchone()[0]==1


def test_outbox_offline_recovery_replay_and_revocation(api,admin_token,tmp_path):
    dev=setup_device(api,admin_token)
    cfg=dict(config(tmp_path),server_base_url='http://127.0.0.1:1',device_token=dev['token'])
    for name in ['SessionStart','PreToolUse','PostToolUse','SessionEnd']:capture(cfg,'codex',payload(name))
    assert flush(cfg)['pending']==1
    box=Outbox(cfg['state_dir'])
    with box.db:box.db.execute('UPDATE outbox SET next_attempt=0')
    box.close()
    cfg['server_base_url']=api.base
    assert flush(cfg)['sent']==4
    box=Outbox(cfg['state_dir'])
    # Simulate crash after server accepted data, before local ack.
    with box.db:box.db.execute("UPDATE outbox SET state='inflight',next_attempt=0")
    box.close()
    assert flush(cfg)['sent']==4
    executions=call(api.base,'GET','/api/v1/executions',token=admin_token).json()['executions']
    assert len(executions)==1 and executions[0]['intent_count']==1 and executions[0]['outcome']=='completed'
    call(api.base,'PATCH','/api/devices/'+dev['device_id'],token=admin_token,body={'status':'revoked'})
    capture(cfg,'codex',dict(payload('SessionStart'),session_id='s2'))
    assert flush(cfg)['dead']==1


def test_install_restore_exact_bytes_and_refuse_overwrite(tmp_path):
    from endpoint.install import install, uninstall
    home=tmp_path/'home';root=tmp_path/'source';root.mkdir()
    original=b'{ "env": {"EXISTING":"kept"}, "hooks": {} }\n'
    settings=home/'.claude/settings.json';settings.parent.mkdir(parents=True);settings.write_bytes(original)
    path=home/'.asgp/endpoint/config.json'
    install(home,root,path,['claude-code'])
    assert install(home,root,path,['claude-code'])==[('claude-code','already_installed')]
    installed=settings.read_bytes()
    settings.write_bytes(installed+b'\n')
    with pytest.raises(RuntimeError,match='changed'):uninstall(path)
    settings.write_bytes(installed)
    assert uninstall(path)==['claude-code']
    assert settings.read_bytes()==original


def test_codex_ask_is_denied_and_binary_change_downgrades_observation(tmp_path):
    cfg=config(tmp_path)
    cfg.update(fail_mode='deny',verified_decisions={'codex':'0.166.0'},ask_patterns=['echo'])
    response=json.loads(capture(cfg,'codex',payload('PreToolUse')))
    assert response['hookSpecificOutput']['permissionDecision']=='deny'
    cfg['binary_fingerprints']={'codex':{'path':str(tmp_path/'missing'),'stat':[0,0,0,0]}}
    assert capture(cfg,'codex',dict(payload('PreToolUse'),session_id='changed'))==''
    box=Outbox(cfg['state_dir'])
    rows=[json.loads(r[0]) for r in box.db.execute("select payload from outbox where endpoint='/api/v1/executions'")]
    assert any(row['product_version']=='unverified-changed' for row in rows)
