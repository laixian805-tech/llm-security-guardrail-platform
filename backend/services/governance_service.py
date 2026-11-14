"""确定性风险/策略及准入、Incident 状态机；不把状态声明当外部安装证据。"""
from __future__ import annotations

import uuid
from datetime import datetime,timezone
from domain import Admission, Incident, IncidentEvidence, PolicyDecision, RiskAssessment, RiskDimension
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

# --- 风险评分规则 ---------------------------------------------------------
# 每个维度一条规则，规则本体可读：用了什么证据、怎么映射成分数、置信度由什么
# 决定。置信度一律由证据充分度计算，不允许人工填写——填出来的置信度无法复核，
# 也无法回答"凭什么说这次评估可信"。
RULE_INTRINSIC='risk-v1-intrinsic-severity-max'
RULE_RUNTIME='risk-v1-runtime-event-class'
RULE_EXPOSURE='risk-v1-exposure-declared'
RULE_OVERALL='risk-v1-max-per-dimension'

# 严重度 → 分数。取档位代表值而不是连续函数：策略阈值按档比较，连续值会让
# "high 到底算 75 还是 74"取决于实现细节。
SEVERITY_LEVEL=LEVEL

# 运行事件的分类分值。网络出口只是观测，不是外泄证据，所以低于文件/进程类。
RUNTIME_EVENT_SCORE={'network_connect':25}
RUNTIME_DEFAULT_SCORE=10

# 暴露因子权重。这是声明值，不是测量值——权重可以讨论，但"它没有被独立测量"
# 这件事必须体现在置信度里，而不是只写在 reasons 的散文里。
EXPOSURE_WEIGHTS={'privileged':80,'network_access':25,'untrusted_source':50}

# 置信度等级顺序，用于"多个独立检测器相互印证时升一级"。
_RANK={Confidence.UNKNOWN:0,Confidence.LOW:1,Confidence.MEDIUM:2,Confidence.HIGH:3}
_BY_RANK={v:k for k,v in _RANK.items()}


def _promote(confidence,steps=1):
    return _BY_RANK[min(_RANK[Confidence.HIGH],_RANK[confidence]+steps)]


def _cap(confidence,ceiling):
    """按等级顺序取较低者。

    不能写 ``min(a, b)``：Confidence 是 StrEnum，min 会按字符串比较，于是
    ``min(HIGH, MEDIUM)`` 返回 HIGH——MEDIUM 上限会被静默绕过。
    """
    return _BY_RANK[min(_RANK[confidence],_RANK[ceiling])]


def _intrinsic_dimension(findings):
    """固有风险 = 最强 finding 的严重度档位分。

    置信度由两件事决定：finding 自己声明的置信度（取最弱的一条，评估不强于
    其最弱证据），以及是否有多个独立检测器印证同一严重度档。单一检测器的
    结论再高也只到 MEDIUM——没有独立确认的"严重"只是一个人的判断。
    """
    if not findings:
        return RiskDimension(dimension='intrinsic',score=0,confidence=Confidence.UNKNOWN,
            rule_version=RULE_INTRINSIC,
            basis='无 finding 证据：该维度未测量。0 分表示没有数据，不等于没有风险。',
            evidence_refs=[])
    # 分数取最高严重度档，置信度只由支撑这一档的 finding 决定。两者不能用同一
    # 条 finding：最低置信度的那条可能只是 info，拿它定档会把最严重的问题藏起来。
    peak=max(SEVERITY_LEVEL[f['severity']] for f in findings)
    band=[f for f in findings if SEVERITY_LEVEL[f['severity']]==peak]
    worst=min(band,key=lambda f:_RANK[f['confidence']])
    detectors={f['detector_id'] for f in band}
    confidence=_promote(worst['confidence']) if len(detectors)>1 else _cap(
        worst['confidence'],Confidence.MEDIUM)
    refs=[EvidenceRef(kind='finding',uri=f['finding_id']) for f in findings]
    basis=(f"{len(findings)} 条 finding，最高严重度 {worst['severity']} → {peak} 分"
           f"（{RULE_INTRINSIC} 严重度档位表）；该档由 {len(band)} 条 finding、"
           f"{len(detectors)} 个检测器（{', '.join(sorted(detectors))}）支撑，"
           f"其中最弱置信度 {worst['confidence'].value}。"
           + ('多个独立检测器印证同一档位，置信度升一级。' if len(detectors)>1
              else '单一检测器结论，置信度上限 MEDIUM：没有独立确认。'))
    return RiskDimension(dimension='intrinsic',score=peak,confidence=confidence,
        rule_version=RULE_INTRINSIC,basis=basis,evidence_refs=refs)


def _runtime_dimension(events):
    """运行风险 = 观测到的最高分类分值。

    置信度取决于这些事件有没有被归因：选中的归因边说明"这次调用确实产生了
    这个现象"，没有归因的主机事件只说明"主机上发生了某事"，对某个执行的
    风险叙事要弱得多。
    """
    if not events:
        return RiskDimension(dimension='runtime',score=0,confidence=Confidence.UNKNOWN,
            rule_version=RULE_RUNTIME,
            basis='无运行事件证据：该维度未测量。0 分表示没有数据，不等于没有风险。',
            evidence_refs=[])
    score=max(RUNTIME_EVENT_SCORE.get(e['event_type'],RUNTIME_DEFAULT_SCORE) for e in events)
    attributed=[e for e in events if e['attributed']]
    if len(attributed)==len(events):
        confidence=Confidence.HIGH
    elif attributed:
        confidence=Confidence.MEDIUM
    else:
        confidence=Confidence.LOW
    kinds=sorted({e['event_type'] for e in events})
    refs=[EvidenceRef(kind='runtime_event',uri='/'.join([e['host_id'],e['collector_id'],e['event_id']]))
          for e in events]
    basis=(f"{len(events)} 条运行事件，分类 {', '.join(kinds)}，最高分值 {score}"
           f"（{RULE_RUNTIME}）；其中 {len(attributed)} 条有选中归因。"
           + ('全部有归因，置信度高。' if len(attributed)==len(events)
              else '部分事件无归因，只能说明主机上发生过，不能证明由该执行引起。'
              if attributed else '没有任何事件被归因：无法确认这些现象由该执行产生。'))
    return RiskDimension(dimension='runtime',score=score,confidence=confidence,
        rule_version=RULE_RUNTIME,basis=basis,evidence_refs=refs)


def _exposure_dimension(exposure):
    """暴露风险 = 命中因子的最高权重。

    这一维度永远是声明值：调用方自己说"这台以特权运行"，平台没有独立测量
    过。所以只要有因子命中，置信度封顶 LOW——不是低估风险，是不把自述当成
    事实。一个因子都没给时记 UNKNOWN，不记 0。
    """
    hits=[(name,weight) for name,weight in EXPOSURE_WEIGHTS.items() if exposure.get(name)]
    if not hits:
        return RiskDimension(dimension='exposure',score=0,confidence=Confidence.UNKNOWN,
            rule_version=RULE_EXPOSURE,
            basis='未声明任何暴露因子：该维度未测量。0 分表示没有数据，不等于没有风险。',
            evidence_refs=[])
    score=max(weight for _,weight in hits)
    basis=(f"声明因子 {', '.join(f'{name}={weight}' for name,weight in hits)}，"
           f"最高权重 {score}（{RULE_EXPOSURE}）。全部由调用方自述，平台未独立测量，"
           f"置信度封顶 LOW。")
    return RiskDimension(dimension='exposure',score=score,confidence=Confidence.LOW,
        rule_version=RULE_EXPOSURE,basis=basis,evidence_refs=[])


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
        findings=[];events=[];refs=[]
        with self.storage.connection() as c:
            for fid in body.get('finding_ids',[]):
                row=c.execute('SELECT severity,confidence,detector_id FROM findings WHERE finding_id=?',(fid,)).fetchone()
                if not row:raise IngestError('unknown_finding',404)
                findings.append({'severity':row['severity'],'confidence':Confidence(row['confidence']),
                    'detector_id':row['detector_id'],'finding_id':fid})
                refs.append(EvidenceRef(kind='finding',uri=fid))
            for identity in body.get('event_ids',[]):
                if not isinstance(identity,dict) or set(identity)!={'host_id','collector_id','event_id'}:raise IngestError('event_identity_required')
                where=(identity['host_id'],identity['collector_id'],identity['event_id'])
                row=c.execute('SELECT event_type FROM runtime_events WHERE host_id=? AND collector_id=? AND event_id=?',where).fetchone()
                if not row:raise IngestError('unknown_event',404)
                # 选中归因边说明"这个现象确实由该执行产生"；没有边的事件只说明主机上
                # 发生过某事。分数照记（观测不能被丢），但置信度必须反映这个区别。
                attributed=c.execute('SELECT 1 FROM event_attributions WHERE host_id=? AND collector_id=?'
                    ' AND event_id=? AND selected=1',where).fetchone()
                events.append({**identity,'event_type':row['event_type'],'attributed':bool(attributed)})
                refs.append(EvidenceRef(kind='runtime_event',uri='/'.join(identity[k] for k in ['host_id','collector_id','event_id'])))
        exposure=body.get('exposure',{})
        if not isinstance(exposure,dict) or set(exposure)-set(EXPOSURE_WEIGHTS):raise IngestError('invalid_exposure')
        if any(not isinstance(v,bool) for v in exposure.values()):raise IngestError('invalid_exposure')
        dimensions=[_intrinsic_dimension(findings),_runtime_dimension(events),_exposure_dimension(exposure)]
        by_name={d.dimension:d for d in dimensions}
        # 总体置信度 = 参与评分的最弱维度。评估不强于其最弱证据；取平均值或取最强
        # 都会让"这次评估有多可信"变成一句无法复核的话。
        contributing=[d for d in dimensions if d.confidence is not Confidence.UNKNOWN]
        overall=min((d.confidence for d in contributing),key=_RANK.get) if contributing else Confidence.UNKNOWN
        reasons=[f"{d.dimension}: {d.score} 分，置信度 {d.confidence.value}，规则 {d.rule_version}" for d in dimensions]
        model=RiskAssessment(assessment_id='risk_'+uuid.uuid4().hex,asset_id=body.get('asset_id'),execution_id=body.get('execution_id'),
            intrinsic_risk=by_name['intrinsic'].score,runtime_risk=by_name['runtime'].score,exposure_risk=by_name['exposure'].score,
            confidence=overall,reasons=reasons,evidence_refs=refs,dimensions=dimensions,
            rule_version=RULE_OVERALL,created_at=NOW(),updated_at=NOW())
        return self.repo.create(model)

    def evaluate(self,body):
        reject_secrets(body)
        if set(body)-{'assessment_id','subject_kind','subject_id','host_id','product'}:raise IngestError('invalid_policy_input')
        if not all(isinstance(body.get(k),str) and 0<len(body[k])<=160 for k in ('assessment_id','subject_kind','subject_id')):raise IngestError('invalid_policy_input')
        for opt in ('host_id','product'):
            if opt in body and body[opt] is not None and (not isinstance(body[opt],str) or not (0<len(body[opt])<=160)):
                raise IngestError('invalid_policy_input')
        risk=self.repo.get(RiskAssessment,body['assessment_id'])
        if not risk:raise IngestError('unknown_assessment',404)
        # 求值与落库都按当前活跃策略版本；版本号来自版本记录，不写死。
        decision=self.policy.evaluate(
            risk,
            body['subject_kind'],
            body['subject_id'],
            host_id=body.get('host_id'),
            product=body.get('product'),
        )
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
