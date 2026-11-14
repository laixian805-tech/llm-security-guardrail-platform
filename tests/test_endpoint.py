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


def test_codex_ask_is_denied_and_binary_change_fails_closed_in_deny_mode(tmp_path):
    cfg=config(tmp_path)
    cfg.update(fail_mode='deny',verified_decisions={'codex':'0.166.0'},ask_patterns=['echo'])
    response=json.loads(capture(cfg,'codex',payload('PreToolUse')))
    assert response['hookSpecificOutput']['permissionDecision']=='deny'
    cfg['binary_fingerprints']={'codex':{'path':str(tmp_path/'missing'),'stat':[0,0,0,0]}}
    changed=json.loads(capture(cfg,'codex',dict(payload('PreToolUse'),session_id='changed')))
    assert changed['hookSpecificOutput']['permissionDecision']=='deny'
    assert 'unverified-changed' in changed['hookSpecificOutput']['permissionDecisionReason']
    obs_cfg=dict(cfg,fail_mode='observe')
    assert capture(obs_cfg,'codex',dict(payload('PreToolUse'),session_id='changed_obs'))==''
    box=Outbox(cfg['state_dir'])
    rows=[json.loads(r[0]) for r in box.db.execute("select payload from outbox where endpoint='/api/v1/executions'")]
    assert any(row['product_version']=='unverified-changed' for row in rows)


def test_hook_main_fails_closed_on_errors_in_deny_mode(tmp_path, monkeypatch, capsys):
    import hashlib, io
    from endpoint import hook as hook_mod
    cfg_path=tmp_path/'config.json'
    state_dir=tmp_path/'state'
    bin_path=tmp_path/'fake_qwen'
    bin_path.write_bytes(b'original-binary')
    st=bin_path.stat()
    cfg_data={
        'server_base_url':'http://127.0.0.1:8010',
        'state_dir':str(state_dir),
        'product_versions':{'qwen-code':'0.26.8','claude-code':'2.1.152','codex':'0.166.0'},
        'verified_decisions':{'qwen-code':'0.26.8'},
        'fail_mode':'deny',
        'binary_fingerprints':{'qwen-code':{'files':[{'path':str(bin_path),'stat':[st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns],'sha256':hashlib.sha256(b'different').hexdigest()}]}},
    }
    cfg_path.write_text(json.dumps(cfg_data),encoding='utf-8')
    monkeypatch.setenv('ASGP_ENDPOINT_CONFIG',str(cfg_path))
    monkeypatch.setattr(hook_mod.sys,'argv',['endpoint.hook','qwen-code'])

    # sha256 mismatch with identical stat triggers unverified-changed fail-closed deny
    pre_payload={'hook_event_name':'PreToolUse','session_id':'s_sha','tool_name':'run_shell_command','tool_input':{'command':'ls'}}
    monkeypatch.setattr(hook_mod.sys,'stdin',type('S',(),{'buffer':io.BytesIO(json.dumps(pre_payload).encode())})())
    assert hook_mod.main()==0
    out=json.loads(capsys.readouterr().out)
    assert out['hookSpecificOutput']['permissionDecision']=='deny'

    # unknown protocol field exception on PreToolUse in fail_mode=deny -> stdout deny
    bad_payload=dict(pre_payload,unexpected_field='evil')
    monkeypatch.setattr(hook_mod.sys,'stdin',type('S',(),{'buffer':io.BytesIO(json.dumps(bad_payload).encode())})())
    assert hook_mod.main()==0
    out=json.loads(capsys.readouterr().out)
    assert out['hookSpecificOutput']['permissionDecision']=='deny'

    # malformed json on stdin in fail_mode=deny -> stdout deny
    monkeypatch.setattr(hook_mod.sys,'stdin',type('S',(),{'buffer':io.BytesIO(b'{not-json')})())
    assert hook_mod.main()==0
    out=json.loads(capsys.readouterr().out)
    assert out['hookSpecificOutput']['permissionDecision']=='deny'

    # PostToolUse error must not emit PreToolUse deny directive
    post_bad={'hook_event_name':'PostToolUse','session_id':'s_sha','unexpected_field':'x'}
    monkeypatch.setattr(hook_mod.sys,'stdin',type('S',(),{'buffer':io.BytesIO(json.dumps(post_bad).encode())})())
    assert hook_mod.main()==0
    assert capsys.readouterr().out.strip()==''


def test_install_supports_qwen_code_and_uninstall_restores(tmp_path):
    from endpoint.install import install, uninstall
    home=tmp_path/'home';root=tmp_path/'source';root.mkdir()
    settings=home/'.qwen/settings.json';settings.parent.mkdir(parents=True)
    original=b'{\n  "model": "qwen"\n}\n'
    settings.write_bytes(original)
    cfg_path=home/'.asgp/endpoint/config.json'
    assert install(home,root,cfg_path,['qwen-code'])==[('qwen-code','install')]
    data=json.loads(settings.read_text(encoding='utf-8'))
    assert set(data['hooks'].keys())=={'SessionStart','PreToolUse','PostToolUse'}
    assert 'endpoint.hook qwen-code' in data['hooks']['PreToolUse'][0]['hooks'][0]['command']
    assert uninstall(cfg_path)==['qwen-code']
    assert settings.read_bytes()==original


def test_capacity_reclaims_only_acknowledged_records_and_counts_duplicates(tmp_path):
    box=Outbox(tmp_path/'capacity',max_records=2)
    box.enqueue_many([('old','/api',{}),('pending','/api',{})])
    # Exact replay requires no additional slot.
    box.enqueue_many([('pending','/api',{})])
    with box.db:box.db.execute("UPDATE outbox SET state='sent' WHERE record_id='old'")
    box.enqueue_many([('new','/api',{})])
    assert {r[0] for r in box.db.execute('SELECT record_id FROM outbox')}=={'pending','new'}
    with pytest.raises(RuntimeError):box.enqueue_many([('overflow','/api',{})])
    assert {r[0] for r in box.db.execute('SELECT record_id FROM outbox')}=={'pending','new'}


def test_capacity_does_not_evict_records_in_same_replay_batch(tmp_path):
    box=Outbox(tmp_path/'capacity',max_records=2)
    box.enqueue_many([('sent','/api',{}),('pending','/api',{})])
    with box.db:box.db.execute("UPDATE outbox SET state='sent' WHERE record_id='sent'")
    with pytest.raises(RuntimeError,match='capacity'):
        box.enqueue_many([('sent','/api',{}),('new','/api',{})])
    assert box.db.execute('SELECT count(*) FROM outbox').fetchone()[0]==2
