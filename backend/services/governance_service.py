"""确定性风险/策略及准入、Incident 状态机；不把状态声明当外部安装证据。"""
from __future__ import annotations

import uuid
from datetime import datetime,timezone
from domain import Admission, Incident, IncidentEvidence, PolicyDecision, RiskAssessment
from domain.enums import AdmissionState, Confidence, IncidentStatus, Severity
from domain.evidence import EvidenceRef
from services.managed_installer import InstallerError, ManagedInstaller, component
from services.product_installer import ProductInstaller
from services.policy_service import PolicyService
from storage.governance_repositories import GovernanceRepository,StateConflict
from services.ingestion_service import IngestError,reject_secrets

NOW=lambda:datetime.now(timezone.utc)
LEVEL={'unknown':0,'info':5,'low':20,'medium':45,'high':75,'critical':95}
# 安装器真正落过盘的状态：回滚要有确定目标，未提交的事务不能动已安装内容。
INSTALLED_STATES=frozenset({AdmissionState.STAGED,AdmissionState.COMMITTED,AdmissionState.VERIFIED,AdmissionState.RECONCILED,AdmissionState.FAILED})


def _installer_call(operation,*args):
    try:
        return operation(*args)
    except InstallerError as exc:
        raise IngestError(exc.code,exc.status)


class GovernanceService:
    def __init__(self,storage,installer:ManagedInstaller|None=None,policy:PolicyService|None=None,
                 products:ProductInstaller|None=None):
        self.repo=GovernanceRepository(storage)
        self.storage=storage
        self.installer=installer
        self.products=products
        self.policy=policy or PolicyService(storage,self.repo)

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
        # 求值与落库都按当前活跃策略版本；版本号来自版本记录，不写死。
        decision=self.policy.evaluate(risk,body['subject_kind'],body['subject_id'])
        return self.repo.create(decision)

    def check_admission(self,body):
        reject_secrets(body)
        allowed={'asset_instance_id','content_hash','transaction_id','product_id'}
        required={'asset_instance_id','content_hash','transaction_id'}
        if set(body)-allowed or not required<=set(body):raise IngestError('invalid_admission_input')
        digest=body['content_hash']
        if not isinstance(digest,str) or len(digest)!=64 or any(x not in '0123456789abcdef' for x in digest):raise IngestError('invalid_content_hash')
        # 两个标识符都会被安装器用作目录名，先在边界上拒绝路径分量。
        _installer_call(component,body['transaction_id'],'transaction_id')
        _installer_call(component,body['asset_instance_id'],'asset_instance_id')
        product_id=body.get('product_id')
        if product_id is not None:
            if not isinstance(product_id,str) or not product_id:raise IngestError('invalid_admission_input')
            # 两种模式：本机配了产品绑定就按白名单校验；没配表示产品在端侧，
            # 由端侧探测回传证据（控制面连不到被测主机）。
            if self.products is not None and product_id not in self.products.products():
                raise IngestError('unknown_product',400)
        with self.storage.connection() as c:
            row=c.execute('SELECT admission_id,asset_instance_id,content_hash FROM admissions WHERE transaction_id=?',(body['transaction_id'],)).fetchone()
            if row:
                if row['content_hash']!=digest or row['asset_instance_id']!=body['asset_instance_id']:raise IngestError('transaction_id_conflict',409)
                return self.repo.get(Admission,row['admission_id'])
            # 安装中的状态互斥：同一实例同时只允许一个进行中的事务，否则回滚
            # 恢复哪个版本不确定。已验证/已失败/已回滚的实例允许下一轮升级。
            active=c.execute("SELECT admission_id FROM admissions WHERE asset_instance_id=?"
                " AND state IN ('check','approved','staged','committed')",(body['asset_instance_id'],)).fetchone()
            if active:raise IngestError('instance_has_active_admission',409)
        return self.repo.create(Admission(admission_id='admission_'+uuid.uuid4().hex,**body,created_at=NOW(),updated_at=NOW()))

    def _require_installer(self):
        if self.installer is None:
            raise IngestError('installer_required: not_configured',503)
        return self.installer

    def _require_products(self):
        if self.products is None:
            raise IngestError('product_targets_not_configured',503)
        return self.products

    def _finish(self,old,state,actor_id,action,**updates):
        model=old.model_copy(update={'state':state,'updated_at':NOW(),**updates})
        return self.repo.transition(model,previous=old.state.value,actor_id=actor_id,action=action)

    def _fail(self,old,reason,actor_id,action):
        return self._finish(old,AdmissionState.FAILED,actor_id,action,failure_reason=reason)

    def _admission_stage(self,old,body,actor_id):
        if old.state is AdmissionState.STAGED:return old
        if old.state is not AdmissionState.APPROVED:raise IngestError('invalid_admission_transition',409)
        if set(body)!={'source_path'}:raise IngestError('invalid_admission_input')
        installer=self._require_installer()
        observed=_installer_call(installer.stage,old.transaction_id,body['source_path'])
        if observed!=old.content_hash:
            # 暂存内容与审批声明不一致：尚未做任何安装动作即判失败。
            _installer_call(installer.discard_staging,old.transaction_id)
            return self._fail(old,'content_drift: staged hash does not match approved content_hash',actor_id,'stage')
        return self._finish(old,AdmissionState.STAGED,actor_id,'stage',observed_content_hash=observed,failure_reason=None)

    def _admission_commit(self,old,body,actor_id):
        if old.state is AdmissionState.COMMITTED:return old
        if old.state is not AdmissionState.STAGED:raise IngestError('invalid_admission_transition',409)
        if body:raise IngestError('invalid_admission_input')
        installer=self._require_installer()
        try:
            observed,rollback_ref=_installer_call(installer.commit,old.transaction_id,old.asset_instance_id,old.content_hash)
        except IngestError as exc:
            if exc.code!='content_drift':raise
            return self._fail(old,'content_drift: staged content changed after approval',actor_id,'commit')
        # 平台存储落地后，还要把同一份内容放进产品真正的技能目录。产品侧失败
        # 必须回滚平台提交，否则会留下"平台说已装、产品里没有"的半成品。
        # 源取 installed 而不是 staging：commit 已把 staging 原子替换成 installed。
        product_target=product_rollback=None
        verification=None
        if old.product_id and self.products is not None:
            products=self.products
            try:
                result=_installer_call(products.install,old.product_id,old.asset_instance_id,
                    installer.root/'installed'/old.asset_instance_id,old.content_hash)
            except IngestError as exc:
                _installer_call(installer.rollback,old.asset_instance_id,rollback_ref)
                return self._fail(old,f'product_install_failed: {exc.code}',actor_id,'commit')
            product_target,product_rollback=result['target'],result['rollback_ref']
        elif old.product_id:
            # 产品在端侧：控制面只落平台托管，产品安装与探测由端侧执行并回传。
            # 在回传之前，activation 必须保持"未验证"，不能因为"平台已提交"就说已启用。
            verification='pending_endpoint'
        return self._finish(old,AdmissionState.COMMITTED,actor_id,'commit',
            observed_content_hash=observed,rollback_ref=rollback_ref,
            product_target=product_target,product_rollback_ref=product_rollback,
            product_verification=verification,failure_reason=None)

    def _admission_verify(self,old,body,actor_id):
        # verify: committed → verified；reconcile: verified → reconciled。
        # 两者都重算落盘哈希，目标态由当前状态决定，重复调用不改变状态。
        target=AdmissionState.VERIFIED if old.state is AdmissionState.COMMITTED else AdmissionState.RECONCILED
        if old.state is target:return old
        source=AdmissionState.COMMITTED if target is AdmissionState.VERIFIED else AdmissionState.VERIFIED
        if old.state is not source:raise IngestError('invalid_admission_transition',409)
        if body:raise IngestError('invalid_admission_input')
        action='verify' if target is AdmissionState.VERIFIED else 'reconcile'
        installer=self._require_installer()
        observed=_installer_call(installer.verify,old.asset_instance_id)
        if observed!=old.content_hash:
            return self._fail(old,'installed_content_mismatch: on-disk hash does not match approved content_hash',actor_id,action)
        # 有目标产品时，平台哈希通过还不够：要确认产品真的会加载它。
        loaded=verification=None
        if old.product_id and self.products is not None:
            products=self.products
            try:
                result=products.verify(old.product_id,old.asset_instance_id,old.content_hash,probe=True)
            except InstallerError as exc:
                raise IngestError(exc.code,exc.status)
            if result['level']=='product_session':
                loaded=result['loaded'];verification='product_session'
                if loaded is False:
                    return self._fail(old,'product_skill_not_loaded: product session does not recognize this skill',actor_id,action)
                if loaded is None:
                    # 会话跑通但结论不确定（缺凭据/超时/模型报错）：不判失败，
                    # 也绝不记成已加载，等级里写明原因。
                    verification=f"product_session:{result['probe'].get('outcome')}"
            else:
                # 探测不可用：文件级通过，但加载未验证。标注等级，不冒充已生效。
                loaded=None;verification=f"{result['level']}:{result['probe']}"
        elif old.product_id:
            # 产品在端侧：沿用端侧已回传的证据。没回传就是未验证，不能自己补一个。
            loaded=old.product_loaded
            verification=old.product_verification or 'pending_endpoint'
        return self._finish(old,target,actor_id,action,observed_content_hash=observed,
            product_loaded=loaded,product_verification=verification,failure_reason=None)

    def _admission_rollback(self,old,body,actor_id):
        if old.state is AdmissionState.ROLLED_BACK:return old
        if old.state not in INSTALLED_STATES:raise IngestError('invalid_admission_transition',409)
        if body:raise IngestError('invalid_admission_input')
        installer=self._require_installer()
        outcome=_installer_call(installer.rollback,old.asset_instance_id,old.rollback_ref)
        product_outcome='noop'
        if old.product_id and old.product_rollback_ref:
            products=self._require_products()
            product_outcome=_installer_call(products.remove,old.product_id,old.asset_instance_id,old.product_rollback_ref)
        return self._finish(old,AdmissionState.ROLLED_BACK,actor_id,'rollback',
            product_loaded=False,failure_reason=f'rolled_back: {outcome}; product: {product_outcome}')

    def admission_transition(self,identifier,action,body,actor_id):
        reject_secrets(body)
        old=self.repo.get(Admission,identifier)
        if not old:raise IngestError('unknown_admission',404)
        if action=='approve':
            if old.state is AdmissionState.APPROVED:return old
            if old.state is not AdmissionState.CHECK:raise IngestError('invalid_admission_transition',409)
            if body:raise IngestError('invalid_admission_input')
            return self._finish(old,AdmissionState.APPROVED,actor_id,'approve',approved_by=actor_id,failure_reason=None)
        if action not in {'stage','commit','verify','reconcile','rollback'}:raise IngestError('invalid_admission_action')
        # stage/commit/verify/reconcile/rollback 每次转移都伴随真实文件系统后果，
        # 没有任何 body 布尔值可以代替安装证据。
        handlers={'stage':self._admission_stage,'commit':self._admission_commit,
            'verify':self._admission_verify,'reconcile':self._admission_verify,'rollback':self._admission_rollback}
        return handlers[action](old,body,actor_id)

    def record_product_verification(self,identifier,body):
        """端侧探测回传：把产品侧真实证据写进准入记录。

        边界很明确——这里只记录"端侧测到了什么"，不改安装状态机、不接受客户端
        自己声明"我已加载"。``loaded`` 三态必须保留：True 是产品会话确认，
        False 是产品否认，None 是探测没给出结论；把 None 折成 False 或 True
        都会让激活状态说谎。
        """
        reject_secrets(body)
        allowed={'product_id','observed_hash','level','loaded','target','probe_outcome'}
        if set(body)-allowed or 'product_id' not in body or 'level' not in body:
            raise IngestError('invalid_product_verification')
        old=self.repo.get(Admission,identifier)
        if not old:raise IngestError('unknown_admission',404)
        if old.product_id != body['product_id']:
            raise IngestError('product_mismatch',409)
        level=body['level']
        if level not in ('product_session','filesystem'):
            raise IngestError('invalid_verification_level')
        loaded=body.get('loaded')
        if loaded is not None and not isinstance(loaded,bool):
            raise IngestError('invalid_loaded_flag')
        observed=body.get('observed_hash')
        if observed is not None and observed != old.content_hash:
            # 端侧落盘内容和审批声明不一致：证据不可用，不写入"已加载"。
            raise IngestError('product_content_mismatch',409)
        target=body.get('target')
        if target is not None and (not isinstance(target,str) or len(target)>500):
            raise IngestError('invalid_product_target')
        verdict=('product_session' if level=='product_session'
            else f"filesystem:{body.get('probe_outcome') or 'unknown'}")
        stamp=NOW().isoformat()
        with self.storage._lock,self.storage.connection() as c:
            c.execute('UPDATE admissions SET product_target=?,product_loaded=?,product_verification=?,updated_at=?'
                ' WHERE admission_id=?',(target,None if loaded is None else int(loaded),verdict,stamp,identifier))
            # 同状态转换也留痕：时间线要能看到"谁在什么时候给出了产品侧证据"。
            c.execute('INSERT INTO governance_transitions (entity_kind,entity_id,from_state,to_state,actor_id,action,occurred_at)'
                ' VALUES (?,?,?,?,?,?,?)',('admissions',identifier,old.state.value,old.state.value,
                'endpoint','product_verification',stamp))
        # 直接回给 HTTP 层，必须是可序列化字典——返回 Pydantic 模型会让 _send 抛 TypeError。
        return self.repo.get(Admission,identifier).model_dump(mode='json')

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
