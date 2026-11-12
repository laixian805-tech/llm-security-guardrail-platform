#!/usr/bin/env python3
"""离线可复跑的真实 HTTP/CLI 联调；fixture 来自测试机真实产品。"""
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))
from adapters.products.capabilities import PRODUCT_VERSIONS  # noqa: E402

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


def main():
    with tempfile.TemporaryDirectory(prefix='asgp-e2e-') as tmp:
        state=Path(tmp);password=secrets.token_urlsafe(24)
        with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        base=f'http://127.0.0.1:{port}'
        env=dict(os.environ,FUSION_DB_PATH=str(state/'control.db'),FUSION_SCAN_ROOT=str(state/'workspace'),
                 FUSION_ADMIN_PASSWORD=password,FUSION_BIND='127.0.0.1',PORT=str(port))
        with (state/'server.log').open('w') as log:
            server=subprocess.Popen([sys.executable,str(ROOT/'backend/server.py')],cwd=ROOT,env=env,stdout=log,stderr=log)
            def request(path,body=None,token=None,method=None):
                headers={'Content-Type':'application/json'}
                if token:headers['Authorization']='Bearer '+token
                req=urllib.request.Request(base+path,data=json.dumps(body).encode() if body is not None else None,headers=headers,method=method)
                with urllib.request.urlopen(req,timeout=10) as response:return json.load(response)
            try:
                for attempt in range(50):
                    try:
                        session=request('/api/session',{'username':'admin','password':password});break
                    except OSError:
                        if server.poll() is not None:raise RuntimeError('control plane failed to start')
                        time.sleep(.1)
                else:raise RuntimeError('startup timeout')
                device=request('/api/devices',{'label':'fixture-e2e'},session['token'])
                request('/api/devices/'+device['device_id'],{'host_id':'fixture-host'},session['token'],method='PATCH')
                config={'server_base_url':base,'device_token':device['token'],'state_dir':str(state/'endpoint'),
                        'product_versions':{'codex':PRODUCT_VERSIONS['codex'],'claude-code':PRODUCT_VERSIONS['claude-code']},'fail_mode':'observe'}
                config_path=state/'endpoint-config.json';config_path.write_text(json.dumps(config));config_path.chmod(0o600)
                child_env=dict(os.environ,ASGP_ENDPOINT_CONFIG=str(config_path))
                for product,version in config['product_versions'].items():
                    for event in ['SessionStart','PreToolUse','PostToolUse','SessionEnd']:
                        payload=(ROOT/'tests/fixtures/hooks'/product/version/(event+'.json')).read_bytes()
                        child=subprocess.run([sys.executable,'-m','endpoint.hook',product],input=payload,env=child_env,cwd=ROOT,capture_output=True,timeout=10)
                        assert child.returncode==0 and child.stdout==b'' and child.stderr==b'',product+event
                from endpoint.flush import flush
                from endpoint.outbox import Outbox
                assert flush(config)['sent']==8
                rows=request('/api/v1/executions',token=session['token'])['executions']
                assert len(rows)==2 and all(row['intent_count']==1 for row in rows)
                for row in rows:
                    timeline=request('/api/v1/executions/'+row['execution_id']+'/timeline',token=session['token'])
                    assert len(timeline['entries'])==1 and timeline['attribution_supported'] is True
                    assert timeline['entries'][0]['data']['params_summary'].find('values_omitted')>=0
                box=Outbox(config['state_dir'])
                with box.db:box.db.execute("UPDATE outbox SET state='inflight',next_attempt=0")
                box.close();assert flush(config)['sent']==8
                assert len(request('/api/v1/executions',token=session['token'])['executions'])==2
                # Revoke then replay: permanent refusal, no retry loop.
                request('/api/devices/'+device['device_id'],{'status':'revoked'},session['token'],method='PATCH')
                box=Outbox(config['state_dir'])
                with box.db:box.db.execute("UPDATE outbox SET state='pending',next_attempt=0")
                box.close();assert flush(config)['dead']==8
                print(json.dumps({'status':'passed','products':['codex','claude-code'],'executions':2,'intents':2,
                    'checks':['real hook CLI','authenticated HTTP ingestion','stable timeline','idempotent replay','revoked token dead queue'],
                    'evidence_level':'recorded-fixture replay; live-product evidence is separate'}))
            finally:
                server.terminate()
                try:server.wait(timeout=5)
                except subprocess.TimeoutExpired:server.kill();server.wait()
    return 0


if __name__=='__main__':raise SystemExit(main())
