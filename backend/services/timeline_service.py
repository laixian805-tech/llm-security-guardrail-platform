"""以稳定键分页，避免时间戳相同的事件重漏。"""
import base64
import json
from datetime import datetime, timezone
from domain.timeline import TimelineEntry, TimelineResponse
from products.registry import ProductCatalog
from services.ingestion_service import IngestError
from storage.asset_repositories import AssetRepository
from storage.execution_repositories import ExecutionRepository, IntentRepository, RuntimeEventRepository
from services.attribution_service import AttributionService


def _moment(value):
    """把 ISO 时间解析成带时区的 datetime；解析不了返回 None。

    时间统一成 tz-aware 再比较：端侧与控制面都用 ``isoformat()`` 写库，但历史
    数据里混过 ``Z`` 结尾的形式，直接比字符串会得出错误的先后关系。
    """
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


class TimelineService:
    def __init__(self, storage):
        self.storage=storage
        self.executions = ExecutionRepository(storage)
        self.intents = IntentRepository(storage)
        self.events = RuntimeEventRepository(storage)
        self.attributions=AttributionService(storage)
        self.assets=AssetRepository(storage)

    def _findings(self, execution_id):
        """分析员显式关联到本次执行的发现项。

        关联登记在 execution_findings 里，带 actor_id 和 note：这是"某位
        分析员认为这条 Finding 与这次执行有关"，不是采集器证明的因果。
        """
        rows=self.assets.findings_for_execution(execution_id)
        for row in rows:
            row['evidence_refs']=json.loads(row['evidence_refs'] or '[]')
        return rows

    def _admissions(self, instance_id, *, started_at=None, ended_at=None):
        """与本次执行时间窗有交集的准入事务。

        只按 asset_instance_id 全量拉会把该实例历史上每一次准入都挂到每条执行
        上（v1 安装、v2 升级、v3 回滚同时出现在一次执行的时间线里），那是过度
        关联，也会把"这次执行时装的是哪个版本"读错。
        判据：事务活跃区间 ``[created_at, updated_at]`` 与执行窗口有交集。
        跨窗口仍未落定的事务、以及窗口内才提交的事务都会被保留。
        """
        if not instance_id:return []
        start=_moment(started_at)
        end=_moment(ended_at) or datetime.now(timezone.utc)
        with self.storage.connection() as c:
            rows=c.execute('SELECT * FROM admissions WHERE asset_instance_id=?'
                ' ORDER BY created_at, admission_id',(instance_id,)).fetchall()
            admissions=[]
            for row in rows:
                created=_moment(row['created_at'])
                updated=_moment(row['updated_at']) or created
                if created is None:continue
                if start is not None and (updated is None or updated < start):continue
                if created > end:continue
                item=dict(row)
                item['transitions']=[dict(t) for t in c.execute(
                    'SELECT from_state,to_state,actor_id,action,occurred_at FROM governance_transitions'
                    ' WHERE entity_kind=? AND entity_id=? ORDER BY seq',
                    ('admissions',row['admission_id'])).fetchall()]
                admissions.append(item)
        return admissions

    def _policy_decisions(self, subjects):
        if not subjects:return []
        marks=','.join('?'*len(subjects))
        with self.storage.connection() as c:
            rows=c.execute(f'SELECT * FROM policy_decisions WHERE subject_id IN ({marks})'
                ' ORDER BY created_at, decision_id',subjects).fetchall()
        return [dict(r) for r in rows]

    def get(self, execution_id, *, limit=100, cursor=None):
        execution = self.executions.get(execution_id)
        if not execution:
            raise IngestError("unknown_execution", 404)
        entries = []
        attributions=self.attributions.list(execution_id)
        runtime_events=self.events.list_for_execution(execution_id)
        identities={(r['host_id'],r['collector_id'],r['event_id']) for r in runtime_events}
        with self.storage.connection() as c:
            for edge in attributions:
                identity=(edge['host_id'],edge['collector_id'],edge['event_id'])
                if identity in identities:continue
                event=c.execute('SELECT * FROM runtime_events WHERE host_id=? AND collector_id=? AND event_id=?',identity).fetchone()
                if event and event['device_id']==execution['device_id']:
                    runtime_events.append(dict(event));identities.add(identity)
        for kind, rows, key in [("intent", self.intents.list_for_execution(execution_id), "intent_id"),
                                 ("runtime_event", runtime_events, "event_id")]:
            for row in rows:
                row = dict(row)
                if kind == "runtime_event":
                    row["evidence_refs"] = json.loads(row["evidence_refs"])
                    row['attributions']=[e for e in attributions if e['event_id']==row['event_id'] and e['collector_id']==row['collector_id'] and e['host_id']==row['host_id']]
                entry_id=row[key] if kind=='intent' else row['collector_id']+':'+row[key]
                entries.append(TimelineEntry(kind=kind, id=entry_id, occurred_at=row["occurred_at"], data=row))

        # finding / admission / policy_decision 三个分段按已存储的引用接入，
        # 不新建任何推断。见 TimelineResponse.section_links。
        findings=self._findings(execution_id)
        admissions=self._admissions(execution['asset_instance_id'],
            started_at=execution['started_at'], ended_at=execution['ended_at'])
        subjects=[execution_id]
        if execution['asset_instance_id']:
            subjects.append(execution['asset_instance_id'])
        subjects.extend(row['finding_id'] for row in findings)
        subjects.extend(row['admission_id'] for row in admissions)
        decisions=self._policy_decisions(subjects)
        for kind, rows, key, when in [("finding", findings, "finding_id", "created_at"),
                                      ("admission", admissions, "admission_id", "created_at"),
                                      ("policy_decision", decisions, "decision_id", "created_at")]:
            for row in rows:
                entries.append(TimelineEntry(kind=kind, id=row[key], occurred_at=row[when], data=row))

        def ordering(entry):
            return (entry.occurred_at.timestamp(), entry.kind, entry.id)
        entries.sort(key=ordering)
        if cursor:
            try:
                value = json.loads(base64.urlsafe_b64decode(cursor.encode()))
                if not isinstance(value, list) or len(value) != 4 or value[0] != execution_id:
                    raise ValueError
                boundary = tuple(value[1:])
                entries = [entry for entry in entries if ordering(entry) > boundary]
            except Exception:
                raise IngestError("invalid_cursor") from None
        page = entries[:limit]
        next_cursor = None
        if len(entries) > limit:
            next_cursor = base64.urlsafe_b64encode(json.dumps([execution_id, *ordering(page[-1])]).encode()).decode()
        descriptor = ProductCatalog().descriptor(execution["product"])
        verification = descriptor.verification.value if descriptor.product_version == execution["product_version"] else "unverified"
        return TimelineResponse(execution_id=execution_id, product=execution["product"],
            product_version=execution["product_version"], host_id=execution["host_id"],
            capability_verification=verification, attributions=attributions, entries=page, next_cursor=next_cursor).model_dump(mode="json")
