"""治理实体持久化与原子状态转换；状态日志保存真实操作者。"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pydantic import BaseModel
from storage.repositories import Storage
from domain.governance import Admission, Incident, PolicyDecision, RiskAssessment

TABLES = {Admission:'admissions', Incident:'incidents', PolicyDecision:'policy_decisions', RiskAssessment:'risk_assessments'}
KEYS = {Admission:'admission_id', Incident:'incident_id', PolicyDecision:'decision_id', RiskAssessment:'assessment_id'}
JSON_FIELDS = {'reasons', 'evidence_refs'}


class StateConflict(ValueError):
    pass


def encode(model):
    data=model.model_dump(mode='json')
    return {k:json.dumps(v,ensure_ascii=False) if k in JSON_FIELDS else int(v) if isinstance(v,bool) else v for k,v in data.items()}


def decode(model, row):
    if row is None:return None
    data=dict(row)
    for key in JSON_FIELDS.intersection(data):data[key]=json.loads(data[key])
    return model.model_validate(data)


class GovernanceRepository:
    def __init__(self, storage: Storage):
        self.storage=storage

    def get(self, model, identifier):
        with self.storage.connection() as c:
            return decode(model,c.execute(f'SELECT * FROM {TABLES[model]} WHERE {KEYS[model]}=?',(identifier,)).fetchone())

    def list(self, model, limit=100):
        with self.storage.connection() as c:
            rows=c.execute(f'SELECT * FROM {TABLES[model]} ORDER BY rowid DESC LIMIT ?',(limit,)).fetchall()
        return [decode(model,row) for row in rows]

    def create(self, model):
        data=encode(model);table=TABLES[type(model)];key=KEYS[type(model)]
        with self.storage._lock,self.storage.connection() as c:
            c.execute(f'INSERT INTO {table} ({",".join(data)}) VALUES ({",".join("?" for _ in data)})',list(data.values()))
        return model

    def transition(self, model, *, previous, actor_id, action):
        cls=type(model);table=TABLES[cls];key=KEYS[cls];identifier=getattr(model,key)
        field='state' if cls is Admission else 'status'
        data=encode(model)
        with self.storage._lock,self.storage.connection() as c:
            cursor=c.execute(f'UPDATE {table} SET '+','.join(k+'=?' for k in data if k!=key)+f' WHERE {key}=? AND {field}=?',
                [v for k,v in data.items() if k!=key]+[identifier,previous])
            if cursor.rowcount!=1:raise StateConflict('concurrent_state_change')
            c.execute('INSERT INTO governance_transitions (entity_kind,entity_id,from_state,to_state,actor_id,action,occurred_at) VALUES (?,?,?,?,?,?,?)',
                (table,identifier,previous,getattr(model,field).value,actor_id,action,datetime.now(timezone.utc).isoformat()))
        return model

    def history(self, kind, identifier):
        with self.storage.connection() as c:
            return [dict(r) for r in c.execute('SELECT * FROM governance_transitions WHERE entity_kind=? AND entity_id=? ORDER BY seq',(kind,identifier))]
