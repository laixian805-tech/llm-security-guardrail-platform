"""风险评分可解释性：每个维度必须能回答"凭什么是这个分、这个置信度"。

总分只有三个数时，"Intrinsic 为什么是 95"只能靠翻代码回答。这里固定住三件
事：分数来自哪条规则、置信度由什么计算（不由人填）、总体置信度等于最弱的
参与维度。没有证据的维度记 UNKNOWN，不记 0——"没测"不能被读成"没有风险"。
"""
from datetime import datetime, timedelta, timezone

import pytest
from adapters.detectors import NormalizedFinding, RawOutput
from domain import Confidence, Severity
from storage.repositories import DetectorRunRepository, Storage
from test_console_auth import api, admin_token, call

BASE = datetime(2026, 11, 12, 12, 0, tzinfo=timezone.utc)


def setup_device(api, admin_token, label='risk'):
    dev = call(api.base, 'POST', '/api/devices', token=admin_token, body={'label': label}).json()
    call(api.base, 'PATCH', '/api/devices/' + dev['device_id'], token=admin_token,
         body={'host_id': 'host_' + label}).raise_for_status()
    return dev


def start_execution(api, dev, execution_id='exec_risk'):
    body = {'execution_id': execution_id, 'session_id': 'sess_' + execution_id, 'product': 'codex',
            'product_version': '0.166.0', 'started_at': BASE.isoformat()}
    call(api.base, 'POST', '/api/v1/executions', token=dev['token'], body=body).raise_for_status()


def add_intent(api, dev, execution_id, intent_id, tool_call_id):
    call(api.base, 'POST', f'/api/v1/executions/{execution_id}/intents', token=dev['token'],
         body={'intent_id': intent_id, 'tool_name': 'exec_command', 'tool_call_id': tool_call_id,
               'hook_event_type': 'pre_tool_use', 'decision': 'allow',
               'occurred_at': BASE.isoformat()}).raise_for_status()


def add_events(api, dev, execution_id, events):
    batch = {'collector_id': 'codex-hook-v1', 'events': [
        dict(event, execution_id=execution_id, occurred_at=BASE.isoformat()) for event in events]}
    call(api.base, 'POST', '/api/v1/runtime-events:batch', token=dev['token'],
         body=batch).raise_for_status()


def add_finding(api, *, detector_id, severity, confidence, rule_id):
    """finding 只能来自真实检测器 run；这里走仓储同一条写入路径。"""
    repo = DetectorRunRepository(api.module.storage)
    run = repo.create_run(detector_id=detector_id, detector_version='1.0.0',
                          target_ref='fixture', mode='static', timeout_seconds=10)
    repo.record_success(run_id=run, raw=RawOutput(report={}, media_type='application/json',
                                                  sha256='a' * 64, byte_length=2),
                        findings=[NormalizedFinding(rule_id=rule_id, title=rule_id,
                                                    severity=severity, confidence=confidence,
                                                    fingerprint=rule_id + '-fp', detector_id=detector_id,
                                                    detector_version='1.0.0')])
    with api.module.storage.connection() as conn:
        return conn.execute('SELECT finding_id FROM detector_run_findings WHERE detector_run_id=?',
                            (run,)).fetchone()[0]


def assess(api, admin_token, **body):
    response = call(api.base, 'POST', '/api/v1/risk-assessments', token=admin_token, body=body)
    assert response.status_code == 200, response.text
    return response.json()


def dimensions(risk):
    return {d['dimension']: d for d in risk['dimensions']}


def test_every_dimension_carries_its_score_provenance(api, admin_token):
    dev = setup_device(api, admin_token)
    start_execution(api, dev)
    add_intent(api, dev, 'exec_risk', 'i1', 'c1')
    add_events(api, dev, 'exec_risk', [
        {'event_id': 'e_linked', 'event_type': 'network_connect', 'intent_ref': 'c1'},
        {'event_id': 'e_orphan', 'event_type': 'observed'},
    ])
    call(api.base, 'POST', '/api/v1/executions/exec_risk/correlate', token=admin_token).raise_for_status()
    critical = add_finding(api, detector_id='det-alpha', severity=Severity.CRITICAL,
                           confidence=Confidence.MEDIUM, rule_id='rule-alpha')
    risk = assess(api, admin_token, execution_id='exec_risk', finding_ids=[critical],
                  event_ids=[{'host_id': 'host_risk', 'collector_id': 'codex-hook-v1', 'event_id': 'e_linked'},
                             {'host_id': 'host_risk', 'collector_id': 'codex-hook-v1', 'event_id': 'e_orphan'}],
                  exposure={'privileged': True})
    dims = dimensions(risk)
    assert set(dims) == {'intrinsic', 'runtime', 'exposure'}
    # 分数、规则版本、依据、引用四件套齐全，缺一件就答不出"凭什么是这个值"。
    for name, dim in dims.items():
        assert dim['rule_version'].startswith('risk-v1-'), name
        assert len(dim['basis']) > 10, name
    assert dims['intrinsic']['score'] == 95 and 'critical' in dims['intrinsic']['basis']
    assert dims['runtime']['score'] == 25 and 'network_connect' in dims['runtime']['basis']
    assert dims['exposure']['score'] == 80 and 'privileged' in dims['exposure']['basis']
    # 总体置信度 = 最弱的参与维度，不是平均值也不是最强项。
    assert [dims[name]['confidence'] for name in ('intrinsic', 'runtime', 'exposure')] == \
        ['medium', 'medium', 'low']
    assert risk['confidence'] == 'low'
    assert risk['intrinsic_risk'] == 95 and risk['runtime_risk'] == 25 and risk['exposure_risk'] == 80
    assert risk['rule_version'] == 'risk-v1-max-per-dimension'


def test_dimensions_survive_the_round_trip(api, admin_token):
    risk = assess(api, admin_token, exposure={'network_access': True})
    stored = [item for item in call(api.base, 'GET', '/api/v1/risk-assessments', token=admin_token).json()['items']
              if item['assessment_id'] == risk['assessment_id']][0]
    assert stored['dimensions'] == risk['dimensions']


def test_no_evidence_is_unknown_not_zero(api, admin_token):
    """空请求体的三个维度都是"未测量"，不能被读成"没有风险"。"""
    risk = assess(api, admin_token)
    assert risk['intrinsic_risk'] == 0 and risk['runtime_risk'] == 0 and risk['exposure_risk'] == 0
    assert risk['confidence'] == 'unknown'
    for dim in risk['dimensions']:
        assert dim['confidence'] == 'unknown'
        assert dim['score'] == 0 and dim['basis']
        assert dim['evidence_refs'] == []


def test_single_detector_is_capped_at_medium_but_two_promote(api, admin_token):
    dev = setup_device(api, admin_token)
    start_execution(api, dev)
    solo = add_finding(api, detector_id='det-solo', severity=Severity.HIGH,
                       confidence=Confidence.HIGH, rule_id='rule-solo')
    solo_risk = assess(api, admin_token, finding_ids=[solo])
    assert dimensions(solo_risk)['intrinsic']['confidence'] == 'medium'
    assert '单一检测器' in dimensions(solo_risk)['intrinsic']['basis']
    # 同一个检测器的两条 critical 不是相互印证：没有第二个独立来源。
    same_detector = add_finding(api, detector_id='det-solo', severity=Severity.CRITICAL,
                                confidence=Confidence.HIGH, rule_id='rule-solo-2')
    still = assess(api, admin_token, finding_ids=[solo, same_detector])
    assert still['intrinsic_risk'] == 95
    assert dimensions(still)['intrinsic']['confidence'] == 'medium'
    # 两个独立检测器命中同一档位才升一级。
    other = add_finding(api, detector_id='det-other', severity=Severity.CRITICAL,
                        confidence=Confidence.MEDIUM, rule_id='rule-other')
    promoted = assess(api, admin_token, finding_ids=[solo, same_detector, other])
    dim = dimensions(promoted)['intrinsic']
    assert dim['score'] == 95 and dim['confidence'] == 'high'
    assert '升一级' in dim['basis'] and 'det-other' in dim['basis'] and 'det-solo' in dim['basis']


def test_peak_band_and_weakest_confidence_are_computed_separately(api, admin_token):
    """定档看最高严重度，定置信度只看支撑该档的证据。

    若两者都用"置信度最弱的那条 finding"，一条 info 就能把 critical 的分数
    一起拖下去——最严重的问题反而看起来最轻微。
    """
    critical = add_finding(api, detector_id='det-a', severity=Severity.CRITICAL,
                           confidence=Confidence.HIGH, rule_id='rule-a-critical')
    noise = add_finding(api, detector_id='det-b', severity=Severity.INFO,
                        confidence=Confidence.LOW, rule_id='rule-b-info')
    risk = assess(api, admin_token, finding_ids=[critical, noise])
    dim = dimensions(risk)['intrinsic']
    assert dim['score'] == 95
    # info 那条不参与定档，所以不影响 intrinsic 的置信度。
    assert dim['confidence'] == 'medium'
    assert 'critical' in dim['basis'] and 'det-a' in dim['basis'] and 'det-b' not in dim['basis']


def test_unattributed_events_lower_runtime_confidence(api, admin_token):
    """没有选中归因边的事件只说明"主机上发生过"，不能算到这个执行头上。"""
    dev = setup_device(api, admin_token)
    start_execution(api, dev)
    add_intent(api, dev, 'exec_risk', 'i1', 'c1')
    add_events(api, dev, 'exec_risk', [
        {'event_id': 'e_linked', 'event_type': 'network_connect', 'intent_ref': 'c1'},
        {'event_id': 'e_orphan', 'event_type': 'network_connect'},
    ])
    call(api.base, 'POST', '/api/v1/executions/exec_risk/correlate', token=admin_token).raise_for_status()
    identity = {'host_id': 'host_risk', 'collector_id': 'codex-hook-v1'}
    partial = assess(api, admin_token, event_ids=[dict(identity, event_id='e_linked'),
                                                  dict(identity, event_id='e_orphan')])
    assert dimensions(partial)['runtime']['confidence'] == 'medium'
    assert '1 条有选中归因' in dimensions(partial)['runtime']['basis']
    full = assess(api, admin_token, event_ids=[dict(identity, event_id='e_linked')])
    assert dimensions(full)['runtime']['confidence'] == 'high'
    none = assess(api, admin_token, event_ids=[dict(identity, event_id='e_orphan')])
    assert dimensions(none)['runtime']['confidence'] == 'low'
    # 同一个事件，归因与否分数相同：观测不能被丢掉，削弱的只是可信程度。
    assert dimensions(none)['runtime']['score'] == dimensions(partial)['runtime']['score'] == 25


def test_declared_exposure_is_never_more_than_low(api, admin_token):
    """暴露因子是调用方自述，平台没有独立测量过，所以置信度封顶 LOW。"""
    risk = assess(api, admin_token, exposure={'privileged': True, 'untrusted_source': True})
    dim = dimensions(risk)['exposure']
    assert dim['score'] == 80 and dim['confidence'] == 'low'
    assert '未独立测量' in dim['basis']
    assert risk['confidence'] == 'low'
    # 没有声明因子是未测量，不是"没有暴露"。
    clean = assess(api, admin_token, exposure={'privileged': False})
    assert dimensions(clean)['exposure']['confidence'] == 'unknown'
    assert clean['confidence'] == 'unknown'


def test_overall_confidence_ignores_unmeasured_dimensions(api, admin_token):
    """未测量的维度不参与"最弱"计算，否则任何空维度都会把总分压成 UNKNOWN。"""
    critical = add_finding(api, detector_id='det-x', severity=Severity.CRITICAL,
                           confidence=Confidence.HIGH, rule_id='rule-x')
    other = add_finding(api, detector_id='det-y', severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH, rule_id='rule-y')
    risk = assess(api, admin_token, finding_ids=[critical, other])
    assert [d['confidence'] for d in risk['dimensions']] == ['high', 'unknown', 'unknown']
    assert risk['confidence'] == 'high'


def test_unknown_evidence_is_rejected_before_any_score_is_computed(api, admin_token):
    assert call(api.base, 'POST', '/api/v1/risk-assessments', token=admin_token,
                body={'finding_ids': ['find_missing']}).status_code == 404
    assert call(api.base, 'POST', '/api/v1/risk-assessments', token=admin_token,
                body={'event_ids': [{'host_id': 'h', 'collector_id': 'c', 'event_id': 'e'}]}).status_code == 404
    assert call(api.base, 'POST', '/api/v1/risk-assessments', token=admin_token,
                body={'exposure': {'privileged': 'yes'}}).status_code == 400
    assert call(api.base, 'POST', '/api/v1/risk-assessments', token=admin_token,
                body={'exposure': {'unknown_factor': True}}).status_code == 400
