"""确定性风险/策略及准入、Incident 状态机；不把状态声明当外部安装证据。"""
from __future__ import annotations

import uuid
from datetime import datetime,timezone,timedelta
from domain import Admission, Incident, IncidentEvidence, PolicyDecision, RiskAssessment
from domain.enums import AdmissionState, Confidence, IncidentStatus, PolicyAction, Severity
from domain.evidence import EvidenceRef
from storage.governance_repositories import GovernanceRepository,StateConflict
from services.ingestion_service import IngestError,reject_secrets

NOW=lambda:datetime.now(timezone.utc)
LEVEL={'unknown':0,'info':5,'low':20,'medium':45,'high':75,'critical':95}


class GovernanceService:
    def __init__(self,storage):
        self.repo=GovernanceRepository(storage)
        self.storage=storage

    def risk(self,body):
        reject_secrets(body)
        allowed={'asset_id','execution_id','finding_ids','event_ids','exposure'}
        if set(body)-allowed:raise IngestError('invalid_risk_input')
        for field in ('finding_ids','event_ids'):
            values=body.get(field,[])
            if not isinstance(values,list) or len(values)>100:raise IngestError('invalid_risk_evidence_list')
        refs=[];intrinsic=runtime=0;reasons=[]
        with self.storage.connection() as c:
            for fid in body.get('finding_ids',[]):
                row=c.execute('SELECT severity FROM findings WHERE finding_id=?',(fid,)).fetchone()
                if not row:raise IngestError('unknown_finding',404)
                intrinsic=max(intrinsic,LEVEL[row['severity']]);refs.append(EvidenceRef(kind='finding',uri=fid))
            for identity in body.get('event_ids',[]):
                if not isinstance(identity,dict) or set(identity)!={'host_id','collector_id','event_id'}:raise IngestError('event_identity_required')
                row=c.execute('SELECT event_type,result FROM runtime_events WHERE host_id=? AND collector_id=? AND event_id=?',
                    (identity['host_id'],identity['collector_id'],identity['event_id'])).fetchone()
                if not row:raise IngestError('unknown_event',404)
                # Mere network activity is observation, not proof of malicious exfiltration.
                runtime=max(runtime,25 if row['event_type']=='network_connect' else 10)
                refs.append(EvidenceRef(kind='runtime_event',uri='/'.join(identity[k] for k in ['host_id','collector_id','event_id'])))
        exposure=body.get('exposure',{})
        if not isinstance(exposure,dict) or set(exposure)-{'privileged','network_access','untrusted_source'}:raise IngestError('invalid_exposure')
        if any(not isinstance(v,bool) for v in exposure.values()):raise IngestError('invalid_exposure')
        score=max([weight for name,weight in [('privileged',80),('network_access',25),('untrusted_source',50)] if exposure.get(name)]+[0])
        reasons=['intrinsic: strongest observed finding','runtime: observed activity only','exposure: declared context, not independently measured']
        model=RiskAssessment(assessment_id='risk_'+uuid.uuid4().hex,asset_id=body.get('asset_id'),execution_id=body.get('execution_id'),
            intrinsic_risk=intrinsic,runtime_risk=runtime,exposure_risk=score,confidence=Confidence.MEDIUM if refs else Confidence.UNKNOWN,
            reasons=reasons,evidence_refs=refs,rule_version='risk-v1-max-per-dimension',created_at=NOW(),updated_at=NOW())
        return self.repo.create(model)

    def evaluate(self,body):
        reject_secrets(body)
        if set(body)-{'assessment_id','subject_kind','subject_id'}:raise IngestError('invalid_policy_input')
        if not all(isinstance(body.get(k),str) and 0<len(body[k])<=160 for k in ('assessment_id','subject_kind','subject_id')):raise IngestError('invalid_policy_input')
        risk=self.repo.get(RiskAssessment,body['assessment_id'])
        if not risk:raise IngestError('unknown_assessment',404)
        action=PolicyAction.BLOCK if risk.intrinsic_risk>=90 else PolicyAction.CONFIRM if risk.intrinsic_risk>=70 or risk.exposure_risk>=80 else PolicyAction.AUDIT if max(risk.intrinsic_risk,risk.runtime_risk,risk.exposure_risk)>0 else PolicyAction.ALLOW
        model=PolicyDecision(decision_id='decision_'+uuid.uuid4().hex,action=action,policy_version='policy-v1',subject_kind=body['subject_kind'],subject_id=body['subject_id'],
            reason='deterministic per-dimension policy; no enforcement asserted',evidence_refs=[EvidenceRef(kind='risk_assessment',uri=risk.assessment_id)],created_at=NOW(),expires_at=NOW()+timedelta(minutes=10))
        return self.repo.create(model)

    def check_admission(self,body):
        reject_secrets(body)
        allowed={'asset_instance_id','content_hash','transaction_id'}
        if set(body)!=allowed:raise IngestError('invalid_admission_input')
        digest=body['content_hash']
        if not isinstance(digest,str) or len(digest)!=64 or any(x not in '0123456789abcdef' for x in digest):raise IngestError('invalid_content_hash')
        with self.storage.connection() as c:
            row=c.execute('SELECT admission_id,asset_instance_id,content_hash FROM admissions WHERE transaction_id=?',(body['transaction_id'],)).fetchone()
        if row:
            if row['content_hash']!=digest or row['asset_instance_id']!=body['asset_instance_id']:raise IngestError('transaction_id_conflict',409)
            return self.repo.get(Admission,row['admission_id'])
        return self.repo.create(Admission(admission_id='admission_'+uuid.uuid4().hex,**body,created_at=NOW(),updated_at=NOW()))

    def admission_transition(self,identifier,action,body,actor_id):
        reject_secrets(body)
        old=self.repo.get(Admission,identifier)
        if not old:raise IngestError('unknown_admission',404)
        targets={'approve':AdmissionState.APPROVED,'stage':AdmissionState.STAGED,'commit':AdmissionState.COMMITTED,'verify':AdmissionState.VERIFIED,'reconcile':AdmissionState.RECONCILED,'rollback':AdmissionState.ROLLED_BACK}
        expected={'approve':AdmissionState.CHECK,'stage':AdmissionState.APPROVED,'commit':AdmissionState.STAGED,'verify':AdmissionState.COMMITTED,'reconcile':AdmissionState.VERIFIED}
        if action not in targets:raise IngestError('invalid_admission_action')
        # Stage/commit/verify require an actual installer; no body boolean can assert it.
        if action in {'stage','commit','verify','reconcile','rollback'}:
            raise IngestError('installer_required: state_only_transition_forbidden',409)
        if old.state==targets[action]:return old
        if old.state!=expected[action]:raise IngestError('invalid_admission_transition',409)
        model=old.model_copy(update={'state':targets[action],'approved_by':actor_id,'updated_at':NOW()})
        return self.repo.transition(model,previous=old.state.value,actor_id=actor_id,action=action)

    def create_incident(self,body):
        reject_secrets(body)
        if set(body)-{'title','summary','severity','owner'}:raise IngestError('invalid_incident_input')
        return self.repo.create(Incident(incident_id='incident_'+uuid.uuid4().hex,**body,opened_at=NOW(),updated_at=NOW()))

    def incident_transition(self,identifier,body,actor_id):
        reject_secrets(body)
        if set(body)-{'status','owner','retest_passed'}:raise IngestError('invalid_incident_update')
        old=self.repo.get(Incident,identifier)
        if not old:raise IngestError('unknown_incident',404)
        target=IncidentStatus(body.get('status',old.status))
        transitions={IncidentStatus.OPEN:{IncidentStatus.INVESTIGATING},IncidentStatus.INVESTIGATING:{IncidentStatus.CONFIRMED,IncidentStatus.FALSE_POSITIVE},IncidentStatus.CONFIRMED:{IncidentStatus.MITIGATING},IncidentStatus.MITIGATING:{IncidentStatus.VERIFYING},IncidentStatus.VERIFYING:{IncidentStatus.CLOSED,IncidentStatus.MITIGATING},IncidentStatus.FALSE_POSITIVE:{IncidentStatus.CLOSED},IncidentStatus.CLOSED:{IncidentStatus.REOPENED},IncidentStatus.REOPENED:{IncidentStatus.INVESTIGATING}}
        if target!=old.status and target not in transitions.get(old.status,set()):raise IngestError('invalid_incident_transition',409)
        if target==IncidentStatus.CLOSED and old.status!=IncidentStatus.FALSE_POSITIVE:
            # Retest boolean is not sufficient proof: a passed DetectorRun link is required.
            with self.storage.connection() as c:
                passed=c.execute("""SELECT 1 FROM incident_evidence e
                    JOIN detector_runs d ON d.detector_run_id=e.evidence_id
                    WHERE e.incident_id=? AND e.evidence_kind='retest_run'
                    AND d.status='succeeded' AND d.finding_count=0 AND d.started_at>=?
                    AND EXISTS (
                        SELECT 1 FROM incident_evidence original
                        JOIN detector_run_findings links ON links.finding_id=original.evidence_id
                        JOIN detector_runs scan ON scan.detector_run_id=links.detector_run_id
                        WHERE original.incident_id=e.incident_id AND original.evidence_kind='finding'
                        AND scan.target_ref=d.target_ref AND scan.detector_id=d.detector_id
                    )""",(identifier,old.opened_at.isoformat())).fetchone()
            if not passed:raise IngestError('clean_retest_evidence_required',409)
        model=Incident.model_validate({**old.model_dump(),'status':target,'owner':body.get('owner',old.owner),'updated_at':NOW(),'closed_at':NOW() if target==IncidentStatus.CLOSED else None})
        return self.repo.transition(model,previous=old.status.value,actor_id=actor_id,action='incident_update')

    def add_evidence(self,identifier,body):
        reject_secrets(body)
        if not self.repo.get(Incident,identifier):raise IngestError('unknown_incident',404)
        value=IncidentEvidence.model_validate({**body,'incident_id':identifier,'added_at':NOW()})
        locations={'finding':('findings','finding_id'),'execution':('executions','execution_id'),'retest_run':('detector_runs','detector_run_id'),'attribution':('event_attributions','attribution_id')}
        if value.evidence_kind not in locations:raise IngestError('unsupported_evidence_kind')
        table,key=locations[value.evidence_kind]
        with self.storage._lock,self.storage.connection() as c:
            if not c.execute(f'SELECT 1 FROM {table} WHERE {key}=?',(value.evidence_id,)).fetchone():raise IngestError('unknown_evidence',404)
            c.execute('INSERT OR IGNORE INTO incident_evidence VALUES (?,?,?,?,?)',(identifier,value.evidence_kind,value.evidence_id,value.note,value.added_at.isoformat()))
        return value
