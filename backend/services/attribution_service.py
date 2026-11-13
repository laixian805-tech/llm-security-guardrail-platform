"""确定性候选关联：精确 Hook ID、进程谱系、资源/时间弱候选。

不按“离谁最近”硬连。无证据时返回空；多个同强候选保留冲突。
"""
from datetime import datetime,timezone
import hashlib,json,re
from domain import EventAttribution,AttributionMethod,Confidence,EvidenceRef
from services.ingestion_service import IngestError

VERSION='attribution-v2'

# 端侧把家目录归一成 ~，控制面对事件路径也必须用同一规则，否则弱关联永远匹配不上。
HOME_PREFIX=re.compile(r'^/(?:home|Users)/[^/]+')


def _hint_form(path):
    """把路径归一成与端侧 resource_hints 同一形态；非路径返回 None。"""
    if not path:return None
    return HOME_PREFIX.sub('~',str(path).rstrip('/.,;:'))


class AttributionService:
    def __init__(self,storage):self.storage=storage

    def correlate(self,execution_id):
        with self.storage.connection() as c:
            execution=c.execute('SELECT * FROM executions WHERE execution_id=?',(execution_id,)).fetchone()
            if not execution:raise IngestError('unknown_execution',404)
            intents=[dict(r) for r in c.execute('SELECT * FROM intents WHERE execution_id=?',(execution_id,))]
            # Unassociated host events are considered only when evidence points to this execution.
            events=[dict(r) for r in c.execute('SELECT * FROM runtime_events WHERE host_id=? AND device_id=? AND (execution_id=? OR execution_id IS NULL) ORDER BY occurred_at',
                (execution['host_id'],execution['device_id'],execution_id))]
        edges=[];anchors={};parents={}
        for event in events:
            ref=event['intent_ref']
            exact=[i for i in intents if ref and ref in (i['intent_id'],i['tool_call_id'])]
            if event['event_type']=='hook_anchor' and event['pid'] is not None and len(exact)==1:
                anchors.setdefault(event['pid'],[]).append(exact[0])
        def seconds(value):return datetime.fromisoformat(value).timestamp()
        for event in events:
            # Process parent observations are applied in event time order, never
            # using a future PID reuse to explain an older event.
            if event['pid'] is not None:
                parents[event['pid']]=event['ppid']
            candidates=[]
            lineage=[]
            for intent in intents:
                if event['intent_ref'] and event['intent_ref'] in (intent['intent_id'],intent['tool_call_id']):
                    candidates.append((intent,AttributionMethod.HOOK_ID,.99))
            if not candidates and event['pid'] is not None:
                pid=event['pid'];visited=set()
                for _ in range(64):
                    if pid in visited or pid is None:break
                    visited.add(pid)
                    lineage.append(pid)
                    if pid in anchors:
                        for intent in anchors[pid]:
                            # PID trees alone are not a timeless identity; require the call interval.
                            start=seconds(intent['occurred_at']);has_end=bool(intent['ended_at'])
                            end=seconds(intent['ended_at']) if has_end else start+30
                            ev_t=seconds(event['occurred_at'])
                            # 已结束的调用（Pre/PostToolUse 同一宿主机时钟闭合）不把前置 Hook 或后置宿主辅助进程拉进直接子进程。
                            if has_end and len(lineage)<=2:
                                if start-0.005<=ev_t<=end+0.005:candidates.append((intent,AttributionMethod.PROCESS_TREE,.85))
                            elif start-1<=ev_t<=end+1:candidates.append((intent,AttributionMethod.PROCESS_TREE,.85))
                        break
                    pid=parents.get(pid)
            if not candidates:
                # Weak candidates require an explicit matching resource hint, not time alone.
                for intent in intents:
                    resource=_hint_form(event['resource_path']) or event['resource_host']
                    try:summary=json.loads(intent['params_summary'])
                    except (ValueError,TypeError):continue
                    if not isinstance(summary,dict):continue
                    # 端侧产出 resource_hints（列表）；resource_hint（单数）是早期字段，
                    # 保留兼容，避免历史 intent 突然失去弱关联。
                    hints=summary.get('resource_hints')
                    if not hints and summary.get('resource_hint'):
                        hints=[summary['resource_hint']]
                    if resource and hints and resource in hints and abs(seconds(event['occurred_at'])-seconds(intent['occurred_at']))<=2:
                        candidates.append((intent,AttributionMethod.TEMPORAL_FEATURE,.35))
            strong=len([x for x in candidates if x[2]>=.8])
            for intent,method,score in candidates:
                key=[intent['intent_id'],event['host_id'],event['collector_id'],event['event_id'],method.value]
                edges.append(EventAttribution(attribution_id='attr_'+hashlib.sha256(json.dumps(key).encode()).hexdigest()[:32],intent_id=intent['intent_id'],
                    event_id=event['event_id'],host_id=event['host_id'],collector_id=event['collector_id'],method=method,
                    confidence=Confidence.HIGH if score>=.95 else Confidence.MEDIUM if score>=.8 else Confidence.LOW,score=score,selected=strong==1 and score>=.8,
                    evidence_refs=[EvidenceRef(kind='runtime_event',uri='/'.join(key[1:4])),EvidenceRef(kind='intent',uri=intent['intent_id'])]
                        +([EvidenceRef(kind='process_lineage',uri='pid-chain:'+'>'.join(str(p) for p in lineage))] if method is AttributionMethod.PROCESS_TREE else []),
                    rule_version=VERSION,created_at=datetime.now(timezone.utc)))
        with self.storage._lock,self.storage.connection() as c:
            for edge in edges:
                c.execute('INSERT INTO event_attributions VALUES (?,?,?,?,?,?,?,?,?,?,?,?) '
                    'ON CONFLICT(intent_id,host_id,collector_id,event_id,method) DO UPDATE SET '
                    'confidence=excluded.confidence,score=excluded.score,selected=excluded.selected,'
                    'evidence_refs=excluded.evidence_refs,rule_version=excluded.rule_version',
                    (edge.attribution_id,edge.intent_id,edge.event_id,edge.host_id,edge.collector_id,edge.method.value,edge.confidence.value,edge.score,int(edge.selected),
                     json.dumps([r.model_dump() for r in edge.evidence_refs]),edge.rule_version,edge.created_at.isoformat()))
            for identity in {(e.host_id,e.collector_id,e.event_id) for e in edges}:
                # An event observed from competing executions remains ambiguous.
                conflicts=c.execute('SELECT COUNT(DISTINCT intent_id) FROM event_attributions WHERE host_id=? AND collector_id=? AND event_id=? AND score>=0.8',identity).fetchone()[0]
                if conflicts>1:
                    c.execute('UPDATE event_attributions SET selected=0 WHERE host_id=? AND collector_id=? AND event_id=?',identity)
        stored=self.list(execution_id)
        # 三个计数必须分开，否则"没有候选"和"有候选但不敢选"会被读成同一个数。
        # hook_anchor 是"哪条调用对应哪个 pid"的绑定元数据，不是被归因对象，
        # 把它算进分母会让未归因率凭空变高。
        subjects=[e for e in events if e['event_type']!='hook_anchor']
        covered={(e.host_id,e.collector_id,e.event_id) for e in edges}
        chosen={(e.host_id,e.collector_id,e.event_id) for e in edges if e.selected}
        no_candidate=[e for e in subjects if (e['host_id'],e['collector_id'],e['event_id']) not in covered]
        ambiguous=[e for e in subjects if (e['host_id'],e['collector_id'],e['event_id']) in covered
                   and (e['host_id'],e['collector_id'],e['event_id']) not in chosen]
        return {'execution_id':execution_id,'candidate_count':len(edges),
            'selected_count':sum(e['selected'] for e in stored),
            'subject_count':len(subjects),'no_candidate_count':len(no_candidate),
            'ambiguous_count':len(ambiguous),
            # 没有任何 selected 归因的事件数：两者之和。冲突降级与无候选对下游
            # 的含义不同（前者是"不敢连"，后者是"连不上"），所以分别给出。
            'unattributed_count':len(no_candidate)+len(ambiguous),
            'rule_version':VERSION}

    def list(self,execution_id):
        with self.storage.connection() as c:
            rows=c.execute('SELECT a.* FROM event_attributions a JOIN intents i ON i.intent_id=a.intent_id WHERE i.execution_id=? ORDER BY a.event_id,a.score DESC',(execution_id,)).fetchall()
        result=[]
        for row in rows:
            data=dict(row);data['evidence_refs']=json.loads(data['evidence_refs']);result.append(EventAttribution.model_validate(data).model_dump(mode='json'))
        return result
