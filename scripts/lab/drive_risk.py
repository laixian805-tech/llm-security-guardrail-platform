"""临时驱动脚本：走真实 HTTP 验证风险评分可解释性（不提交）。"""
import importlib
import json
import os
import sys
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

root = Path(tempfile.mkdtemp())
(root / 'workspace').mkdir()
(root / 'workspace' / 'sample.py').write_text('import os\n', encoding='utf-8')
os.environ.update({
    'FUSION_DB_PATH': str(root / 'test.db'),
    'FUSION_SCAN_ROOT': str(root / 'workspace'),
    'FUSION_MANAGED_ROOT': str(root / 'managed'),
    'FUSION_BIND': '127.0.0.1',
    'ASGP_MODEL_PROVIDER': 'stepfun',
})
module = importlib.import_module('server')
module = importlib.reload(module)
server = module.ThreadingHTTPServer(('127.0.0.1', 0), module.Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
base = f'http://127.0.0.1:{server.server_port}'

import httpx
ADMIN = 'admin-passphrase-1234'
os.environ['FUSION_ADMIN_PASSWORD'] = ADMIN
module.auth_service.bootstrap_admin(password=ADMIN)
client = httpx.Client(base_url=base, timeout=30)


def call(method, path, token=None, body=None):
    headers = {'Authorization': f'Bearer {token}'} if token else {}
    return client.request(method, path, json=body, headers=headers)


login = call('POST', '/api/session', body={'username': 'admin', 'password': ADMIN})
login.raise_for_status()
admin = login.json()['token']

dev = call('POST', '/api/devices', token=admin, body={'label': 'risk'}).json()
call('PATCH', '/api/devices/' + dev['device_id'], token=admin, body={'host_id': 'host_risk'}).raise_for_status()

started = datetime.now(timezone.utc).isoformat()
execution = {'execution_id': 'exec_risk', 'session_id': 'sess_risk', 'product': 'codex',
             'product_version': '0.166.0', 'started_at': started}
r = call('POST', '/api/v1/executions', token=dev['token'], body=execution)
r.raise_for_status()

batch = {'collector_id': 'codex-hook-v1', 'events': [
    {'event_id': 'e_attributed', 'execution_id': 'exec_risk', 'event_type': 'network_connect', 'occurred_at': started},
    {'event_id': 'e_orphan', 'execution_id': 'exec_risk', 'event_type': 'observed', 'occurred_at': started},
]}
call('POST', '/api/v1/runtime-events:batch', token=dev['token'], body=batch).raise_for_status()

# finding 只能来自检测器 run；这里按仓储同样的形状直接落库。
storage = module.storage
now = datetime.now(timezone.utc).isoformat()
findings = [
    ('f_crit', 'det-alpha', 'critical', 'medium', 'rule-alpha-1'),
    ('f_high', 'det-beta', 'high', 'high', 'rule-beta-1'),
    ('f_info', 'det-alpha', 'info', 'low', 'rule-alpha-2'),
]
with storage.connection() as c:
    c.execute('INSERT INTO intents (intent_id,execution_id,tool_name,hook_event_type,decision,occurred_at,created_at)'
              " VALUES ('i1','exec_risk','exec_command','pre_tool_use','allow',?,?)", (started, now))
    for fid, detector, severity, confidence, rule in findings:
        c.execute('INSERT INTO findings (finding_id,detector_id,detector_version,rule_id,severity,confidence,'
                  'title,message,fingerprint,status,evidence_refs,created_at,updated_at)'
                  ' VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
                  (fid, detector, '1.0.0', rule, severity, confidence, fid, '', fid + '-fp', 'open', '[]', now, now))
    # 一条选中归因边：只有 e_attributed 能算到这个执行头上。
    c.execute('INSERT INTO event_attributions (attribution_id,intent_id,event_id,host_id,collector_id,method,'
              'confidence,score,selected,evidence_refs,rule_version,created_at)'
              " VALUES ('at_1','i1','e_attributed','host_risk','codex-hook-v1','hook_id','high',0.99,1,'[]','attr-v1',?)", (now,))

body = {'execution_id': 'exec_risk',
        'finding_ids': ['f_crit', 'f_high', 'f_info'],
        'event_ids': [{'host_id': 'host_risk', 'collector_id': 'codex-hook-v1', 'event_id': 'e_attributed'},
                      {'host_id': 'host_risk', 'collector_id': 'codex-hook-v1', 'event_id': 'e_orphan'}],
        'exposure': {'privileged': True}}
r = call('POST', '/api/v1/risk-assessments', token=admin, body=body)
r.raise_for_status()
risk = r.json()
print(json.dumps({k: risk[k] for k in ('intrinsic_risk', 'runtime_risk', 'exposure_risk', 'confidence', 'rule_version', 'reasons')}, indent=2, ensure_ascii=False))
print('--- dimensions ---')
for d in risk['dimensions']:
    print(json.dumps(d, indent=2, ensure_ascii=False))

# 同一份评估落库后必须原样读回（JSON 列不能把 dimensions 弄丢）。
assessment_id = risk['assessment_id']
rows = call('GET', '/api/v1/risk-assessments', token=admin).json()
stored = [x for x in rows['items'] if x['assessment_id'] == assessment_id][0]
assert stored['dimensions'] == risk['dimensions'], 'dimensions 往返不一致'
print('\nround-trip OK, dimensions =', len(stored['dimensions']))

# 策略求值仍按三维分数走，与 dimensions 一致。
policy = call('POST', '/api/v1/policies/evaluate', token=admin,
              body={'assessment_id': assessment_id, 'subject_kind': 'execution', 'subject_id': 'exec_risk'})
policy.raise_for_status()
print('policy:', policy.json()['action'], policy.json()['reason'])

# 无证据维度必须记 UNKNOWN 而不是 0 置信度。
empty = call('POST', '/api/v1/risk-assessments', token=admin, body={}).json()
print('\nempty exposure:', empty['confidence'], [d['confidence'] for d in empty['dimensions']])

# 场景 B：两个独立检测器都在 critical 档 → 升一级；全部事件有归因 → HIGH。
with storage.connection() as c:
    c.execute('INSERT INTO findings (finding_id,detector_id,detector_version,rule_id,severity,confidence,'
              'title,message,fingerprint,status,evidence_refs,created_at,updated_at)'
              " VALUES ('f_crit2','det-gamma','1.0.0','rule-gamma-1','critical','medium','f_crit2','',"
              "'f_crit2-fp','open','[]',?,?)", (now, now))
    c.execute('INSERT INTO event_attributions (attribution_id,intent_id,event_id,host_id,collector_id,method,'
              'confidence,score,selected,evidence_refs,rule_version,created_at)'
              " VALUES ('at_2','i1','e_orphan','host_risk','codex-hook-v1','process_tree','medium',0.85,1,'[]','attr-v1',?)", (now,))
body_b = {'finding_ids': ['f_crit', 'f_crit2'],
          'event_ids': [{'host_id': 'host_risk', 'collector_id': 'codex-hook-v1', 'event_id': 'e_attributed'},
                        {'host_id': 'host_risk', 'collector_id': 'codex-hook-v1', 'event_id': 'e_orphan'}]}
rb = call('POST', '/api/v1/risk-assessments', token=admin, body=body_b).json()
print('\nscenario B:')
for d in rb['dimensions']:
    print(f"  {d['dimension']}: score={d['score']} confidence={d['confidence']}")
print('  overall:', rb['confidence'])
assert [d['confidence'] for d in rb['dimensions']] == ['high', 'high', 'unknown'], rb['dimensions']
assert rb['confidence'] == 'high'
server.shutdown()
