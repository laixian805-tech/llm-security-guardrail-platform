"""上报覆盖度对账：端侧只有它自己知道"本想送多少、实际丢了多少"。

Hook 丢失率与 Audit 丢失率之所以一直测不出来，不是因为难算，而是因为
丢的那一刻没有任何痕迹：outbox 容量封顶直接抛异常，调用方打个日志就完了。
这里把端侧已知的三种丢失（容量封顶、磁盘封顶、审计日志轮转缺口）加上重试
上限的永久失败，汇成一条对账记录送上控制面。

控制面拿它做两件事：
- 丢失率 = 丢失记录数 / 尝试送达记录数；
- 静默检测：有执行、有事件，却长时间没有对账记录的采集器，等于停了。

注意审计轮转缺口的量级是未知的（被轮转走的日志可能有很多条），所以它单独
计数，不并进丢失率的分母——把未知量当成 0 会算出一个看起来很好的比率。
"""
import json
import time
import urllib.error
import urllib.request


def build(outbox, *, period_start, period_end, delivered=0, dead=0):
    """汇总自上次上报以来的丢失与当前积压。

    delivered 必须是本周期增量，不能拿 outbox 的高水位代替：高水位单调累计，
    服务侧把各周期相加时会把分母吹大，丢失率被稀释到看不出来。
    """
    drops = outbox.unreported_drops()
    by_kind = {}
    for row in drops:
        entry = by_kind.setdefault(row['kind'], {'count': 0, 'detail': row['detail']})
        entry['count'] += row['count']
    return {
        'period_start': period_start,
        'period_end': period_end,
        'delivered': int(delivered),
        'dead': int(dead),
        'dropped': by_kind,
        'dropped_records': sum(entry['count'] for entry in by_kind.values()
                               if entry['count'] > 0),
        'unbounded_gaps': sorted(kind for kind, entry in by_kind.items()
                                 if entry['count'] <= 0),
        'backlog': outbox.backlog(),
        'high_water_seq': outbox.high_water(),
    }


def stamp(moment):
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(moment))


def post(config, report, *, timeout=10):
    """上报一条对账记录。失败不抛：对账本身不能把 flush 循环带崩。"""
    body = json.dumps(report, ensure_ascii=False).encode()
    request = urllib.request.Request(config['server_base_url'].rstrip('/')
                                     + '/api/v1/coverage-reports', data=body,
                                     headers={'Authorization': 'Bearer ' + config['device_token'],
                                              'Content-Type': 'application/json'},
                                     method='POST')

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs): return None

    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=timeout) as response:
            json.loads(response.read(1024 * 1024))
        return True
    except (urllib.error.HTTPError, OSError, ValueError):
        return False


def emit(outbox, config, *, period_start, period_end, delivered=0, dead=0):
    """有内容才上报；上报成功才推进游标，失败下次重发同一条。"""
    report = build(outbox, period_start=period_start, period_end=period_end,
                   delivered=delivered, dead=dead)
    if not (report['delivered'] or report['dead'] or report['dropped'] or report['backlog']):
        return None
    report['collector_id'] = config.get('coverage_collector_id', 'endpoint-outbox-v1')
    if not post(config, report):
        return None
    drops = outbox.unreported_drops()
    if drops:
        outbox.mark_drops_reported(drops[-1]['seq'])
    return report
