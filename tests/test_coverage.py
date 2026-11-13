"""覆盖度对账：端侧丢数据必须留痕，服务侧必须能算出比率。

这三件事以前都做不到，所以"Hook 丢失率是多少"一直是说法而不是数字：
端侧 outbox 容量封顶只抛异常，服务侧只看到"没有事件"，分不清"没发生"
和"丢了"。这里固定住整条链路。
"""
import json
import time
import pytest
from test_console_auth import api, admin_token, call


def setup_device(api, admin_token, label='cov', host='host_cov'):
    response = call(api.base, 'POST', '/api/devices', token=admin_token, body={'label': label})
    result = response.json()
    call(api.base, 'PATCH', '/api/devices/' + result['device_id'], token=admin_token,
         body={'host_id': host}).raise_for_status()
    return result


def report(**overrides):
    body = {
        'collector_id': 'endpoint-outbox-v1',
        'period_start': '2026-11-12T00:00:00Z',
        'period_end': '2026-11-12T00:00:05Z',
        'delivered': 100,
        'dead': 1,
        'dropped': {'outbox_capacity_exceeded': {'count': 4}},
        'backlog': 2,
        'high_water_seq': 107,
    }
    body.update(overrides)
    return body


def test_device_reports_coverage_and_console_reads_the_ratio(api, admin_token):
    dev = setup_device(api, admin_token)
    r = call(api.base, 'POST', '/api/v1/coverage-reports', token=dev['token'], body=report())
    assert r.status_code == 200, r.text
    assert r.json()['dropped_records'] == 4

    summary = call(api.base, 'GET', '/api/v1/coverage', token=admin_token).json()
    assert len(summary['hosts']) == 1
    host = summary['hosts'][0]
    # host_id 取自设备绑定值，不采信请求体——否则一台设备能把丢失率算到
    # 别人头上。
    assert host['host_id'] == 'host_cov'
    assert host['delivered'] == 100 and host['lost'] == 5
    assert host['attempted'] == 105
    assert host['loss_rate'] == pytest.approx(5 / 105)
    assert host['warn'] is True
    assert host['drop_kinds'] == {'outbox_capacity_exceeded': 4}


def test_coverage_requires_device_credentials(api, admin_token):
    r = call(api.base, 'POST', '/api/v1/coverage-reports', token=admin_token, body=report())
    assert r.status_code == 401
    assert call(api.base, 'POST', '/api/v1/coverage-reports', body=report()).status_code == 401


def test_rotation_gap_is_never_folded_into_the_loss_rate(api, admin_token):
    """量级未知的缺口不能当 0 记进分母。

    审计日志被轮转走时丢了多少条永远不知道；并进分母会算出一个看起来很好
    的丢失率，正好把最严重的那类丢失藏起来。
    """
    dev = setup_device(api, admin_token)
    call(api.base, 'POST', '/api/v1/coverage-reports', token=dev['token'],
         body=report(delivered=0, dead=0, backlog=0,
                     dropped={'audit_rotation_gap': {'count': 0}})).raise_for_status()
    host = call(api.base, 'GET', '/api/v1/coverage', token=admin_token).json()['hosts'][0]
    assert host['gaps'] == ['audit_rotation_gap']
    assert host['dropped_records'] == 0
    assert host['attempted'] == 0
    assert host['loss_rate'] is None
    assert host['warn'] is True


def test_silent_collector_is_flagged_only_when_the_host_has_executions(api, admin_token):
    """有执行却长时间无对账 = 采集器停了；没有执行却不上报是正常的。"""
    dev = setup_device(api, admin_token)
    call(api.base, 'POST', '/api/v1/coverage-reports', token=dev['token'],
         body=report(period_start='2026-11-11T00:00:00Z',
                     period_end='2026-11-11T00:00:05Z')).raise_for_status()
    host = call(api.base, 'GET', '/api/v1/coverage', token=admin_token).json()['hosts'][0]
    assert host['executions_in_window'] == 0
    assert host['silent'] is False


def test_invalid_coverage_report_is_rejected(api, admin_token):
    dev = setup_device(api, admin_token)
    for body in (report(extra_field=1), report(collector_id=''), report(dropped=[])):
        r = call(api.base, 'POST', '/api/v1/coverage-reports', token=dev['token'], body=body)
        assert r.status_code == 400, body


def test_outbox_records_capacity_drops_that_survive_the_rollback(tmp_path):
    """容量封顶的批次数必须写进 drops，且活过入队事务的回滚。

    在事务内用同一连接写会被外层 `with db:` 回滚掉，痕迹就没了——这正是丢失率长期
    测不出来的直接原因。用独立连接也绕不开：SQLite 只允许一个写者，
    BEGIN IMMEDIATE 还持着锁。所以留痕必须发生在回滚之后。
    """
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from endpoint.outbox import Outbox, enqueue

    box = Outbox(tmp_path / 'endpoint', max_records=2)
    records = [(f'r{i}', '/api/v1/executions', {'execution_id': f'e{i}'}) for i in range(5)]
    with pytest.raises(RuntimeError):
        enqueue(box, records)
    drops = box.unreported_drops()
    assert [row['kind'] for row in drops] == ['outbox_capacity_exceeded']
    assert drops[0]['count'] == 5
    # 事务已回滚：一条都没进队列，但 drops 表仍读到记录。
    assert box.db.execute('SELECT count(*) FROM outbox').fetchone()[0] == 0
    box.mark_drops_reported(drops[-1]['seq'])
    assert box.unreported_drops() == []
    box.close()


def test_audit_rotation_gap_is_registered_as_unbounded(tmp_path):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from endpoint.coverage import build
    from endpoint.outbox import Outbox

    box = Outbox(tmp_path / 'endpoint')
    box.record_drop('audit_rotation_gap', 0,
                    detail='log rotated away before being read; magnitude unknown')
    report = build(box, period_start='2026-11-12T00:00:00Z',
                   period_end='2026-11-12T00:00:05Z', delivered=10)
    assert report['unbounded_gaps'] == ['audit_rotation_gap']
    # count<=0 不计入 dropped_records：那不是"丢了 0 条"，是"不知道丢了多少"。
    assert report['dropped_records'] == 0
    assert report['delivered'] == 10
    box.close()
