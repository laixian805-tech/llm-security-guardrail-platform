"""覆盖度对账：把端侧已知的丢失变成可计算的比率。

Hook 与 Audit 的覆盖度之所以长期不可衡量，根因是丢数据的那一刻没有痕迹。
现在端侧每次容量封顶、重试上限耗尽、审计日志轮转缺口都登记并上报，服务侧
在这里汇总。

两个比率必须分开：
- 丢失率 = 丢失记录数 / 尝试送达记录数。分母是各周期"已送达"之和，不是
  累计高水位——高水位是单调累计值，直接相加会把分母吹大，丢失率被稀释。
- 缺口（unbounded gap）单列。审计日志被轮转走时丢了多少条永远不知道，把它
  当 0 记进分母会得到一个看起来很好的丢失率。

另外做静默检测：一台设备有执行记录却长时间没有对账上报，等于采集器停了
（Hook 被退出、auditd 被停）。这是"攻击者停止审计服务"唯一能被发现的方
式——平台看不到不存在的事件，但看得到"本该说话的人不说话了"。
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

from services.ingestion_service import IngestError
from storage.repositories import now_iso

# 多久没有对账上报就判定采集器静默。取 15 分钟：flush 默认 5s 一个周期，
# 15 分钟相当于 180 个周期全无音讯，不可能是正常的退避重试。
SILENCE_AFTER = timedelta(minutes=15)

# 丢失率超过这个值就应当告警。不是"零丢失才正常"——端侧队列有界，长时断网
# 后一定会有损失；要盯的是比例失控。
LOSS_WARN_ABOVE = 0.01

FIELDS = {'collector_id', 'period_start', 'period_end', 'delivered', 'dead',
          'dropped', 'backlog', 'high_water_seq'}


class CoverageService:
    def __init__(self, storage):
        self.storage = storage

    def record(self, device_id: str, host_id: str, body: dict) -> dict:
        if not isinstance(body, dict) or set(body) - FIELDS:
            raise IngestError('invalid_coverage_report')
        for field in ('collector_id', 'period_start', 'period_end'):
            value = body.get(field)
            if not isinstance(value, str) or not value:
                raise IngestError('invalid_coverage_report')
        dropped = body.get('dropped', {})
        if not isinstance(dropped, dict):
            raise IngestError('invalid_coverage_report')
        counts = {}
        for kind, entry in dropped.items():
            if not isinstance(kind, str) or not isinstance(entry, dict):
                raise IngestError('invalid_coverage_report')
            counts[kind] = max(0, int(entry.get('count', 0) or 0))
        # count<=0 表示"量级未知的缺口"：不是"没丢"，是"不知道丢了多少"。
        gaps = sorted(kind for kind, count in counts.items() if count <= 0)
        record = {
            'report_id': 'cov_' + uuid.uuid4().hex,
            'host_id': host_id,
            'device_id': device_id,
            'collector_id': body['collector_id'],
            'period_start': body['period_start'],
            'period_end': body['period_end'],
            'delivered': max(0, int(body.get('delivered', 0) or 0)),
            'dead': max(0, int(body.get('dead', 0) or 0)),
            'dropped': counts,
            'dropped_records': sum(count for count in counts.values() if count > 0),
            'unbounded_gaps': gaps,
            'backlog': max(0, int(body.get('backlog', 0) or 0)),
            'high_water_seq': max(0, int(body.get('high_water_seq', 0) or 0)),
            'received_at': now_iso(),
        }
        with self.storage._lock, self.storage.connection() as conn:
            conn.execute(
                'INSERT INTO coverage_reports (report_id,host_id,device_id,collector_id,'
                'period_start,period_end,delivered,dead,dropped,dropped_records,'
                'unbounded_gaps,backlog,high_water_seq,received_at)'
                ' VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                (record['report_id'], record['host_id'], record['device_id'],
                 record['collector_id'], record['period_start'], record['period_end'],
                 record['delivered'], record['dead'], json.dumps(record['dropped'], ensure_ascii=False),
                 record['dropped_records'], json.dumps(record['unbounded_gaps'], ensure_ascii=False),
                 record['backlog'], record['high_water_seq'], record['received_at']))
        return record

    def summary(self, *, host_id: str | None = None, window_hours: int = 24) -> dict:
        """按主机汇总丢失率、缺口与静默采集器。"""
        window = max(1, window_hours)
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=window)).isoformat()
        host_clause = ' AND host_id=?' if host_id else ''
        params: tuple = (cutoff, host_id) if host_id else (cutoff,)
        with self.storage.connection() as conn:
            rows = [dict(r) for r in conn.execute(
                'SELECT * FROM coverage_reports WHERE received_at>=?' + host_clause
                + ' ORDER BY received_at DESC LIMIT 5000', params).fetchall()]
            executions = [dict(r) for r in conn.execute(
                'SELECT host_id, count(*) AS total, max(updated_at) AS last FROM executions'
                + (' WHERE host_id=?' if host_id else '') + ' GROUP BY host_id',
                (host_id,) if host_id else ()).fetchall()]
        hosts: dict[str, dict] = {}
        for row in rows:
            entry = hosts.setdefault(row['host_id'], _blank(row['host_id']))
            entry['delivered'] += row['delivered']
            entry['dead'] += row['dead']
            entry['dropped_records'] += row['dropped_records']
            entry['reports'] += 1
            entry['backlog'] = max(entry['backlog'], row['backlog'])
            entry['last_report_at'] = max(entry['last_report_at'] or '', row['received_at'])
            entry['collectors'].add(row['collector_id'])
            for kind in _loads(row['unbounded_gaps']):
                entry['gaps'].add(kind)
            for kind, count in _loads(row['dropped']).items():
                if count > 0:
                    entry['drop_kinds'][kind] = entry['drop_kinds'].get(kind, 0) + count
        activity = {row['host_id']: row for row in executions}
        for identifier, entry in hosts.items():
            lost = entry['dropped_records'] + entry['dead']
            attempted = entry['delivered'] + lost
            entry['attempted'] = attempted
            entry['lost'] = lost
            entry['loss_rate'] = round(lost / attempted, 6) if attempted else None
            entry['warn'] = bool(entry['gaps']) or (
                entry['loss_rate'] is not None and entry['loss_rate'] > LOSS_WARN_ABOVE)
            entry['collectors'] = sorted(entry['collectors'])
            entry['gaps'] = sorted(entry['gaps'])
            entry['drop_kinds'] = dict(sorted(entry['drop_kinds'].items()))
            seen = activity.get(identifier)
            entry['executions_in_window'] = seen['total'] if seen else 0
            entry['last_execution_at'] = seen['last'] if seen else None
            entry['silent'] = _silent(entry, seen)
        return {
            'window_hours': window,
            'silence_after_minutes': int(SILENCE_AFTER.total_seconds() // 60),
            'loss_warn_above': LOSS_WARN_ABOVE,
            'hosts': [hosts[key] for key in sorted(hosts)],
            'active_hosts_without_reports': sorted(set(activity) - set(hosts)),
        }


def _blank(host_id: str) -> dict:
    return {'host_id': host_id, 'reports': 0, 'delivered': 0, 'dead': 0,
            'dropped_records': 0, 'backlog': 0, 'last_report_at': None,
            'collectors': set(), 'gaps': set(), 'drop_kinds': {},
            'executions_in_window': 0, 'last_execution_at': None}


def _silent(entry: dict, seen: dict | None) -> bool:
    """有执行却长时间没有对账上报 = 采集器停了。

    不能只看 last_report_at：从未部署对账的采集器也会没有上报。所以同时要求
    该主机有执行记录——没有执行却不上报是正常的，不是静默。
    """
    if not seen or not entry['last_report_at']:
        return False
    try:
        last = datetime.fromisoformat(entry['last_report_at'])
    except ValueError:
        return False
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - last > SILENCE_AFTER


def _loads(value):
    try:
        return json.loads(value) if value else {}
    except ValueError:
        return {}
