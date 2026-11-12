from datetime import datetime,timezone
from pathlib import Path
import pytest
from test_console_auth import api,admin_token,call,login
from services.governance_service import GovernanceService
from services.managed_installer import tree_hash
from storage.repositories import Storage
from domain.enums import AdmissionState
from domain import Admission,Incident
from pydantic import ValidationError


def test_risk_dimensions_policy_and_state_only_install_forbidden(api,admin_token):
    result=call(api.base,'POST','/api/v1/risk-assessments',token=admin_token,body={'exposure':{'privileged':True}})
    assert result.status_code==200,result.text
    risk=result.json()
    assert risk['intrinsic_risk']==0 and risk['runtime_risk']==0 and risk['exposure_risk']==80
    policy=call(api.base,'POST','/api/v1/policies/evaluate',token=admin_token,body={'assessment_id':risk['assessment_id'],'subject_kind':'test','subject_id':'s'})
    assert policy.status_code==200,policy.text
    assert policy.json()['action']=='confirm' and policy.json()['enforcement_expected'] is False
    data={'asset_instance_id':'asset_1','content_hash':'a'*64,'transaction_id':'transaction_1'}
    r=call(api.base,'POST','/api/v1/admissions/check',token=admin_token,body=data)
    assert r.status_code==200,r.text
    identifier=r.json()['admission_id']
    assert call(api.base,'POST','/api/v1/admissions/check',token=admin_token,body=data).json()['admission_id']==identifier
    assert call(api.base,'POST','/api/v1/admissions/check',token=admin_token,body=dict(data,content_hash='b'*64)).status_code==409
    assert call(api.base,'POST',f'/api/v1/admissions/{identifier}/commit',token=admin_token,body={}).status_code==409
    approved=call(api.base,'POST',f'/api/v1/admissions/{identifier}/approve',token=admin_token,body={})
    assert approved.status_code==200,approved.text
    assert approved.json()['approved_by']
    # A workflow state alone must not pretend actual stage/install/verify happened:
    # stage 需要 inbound 下的真实来源，body 布尔值不能代替安装证据。
    assert call(api.base,'POST',f'/api/v1/admissions/{identifier}/stage',token=admin_token,body={}).status_code==400
    assert call(api.base,'POST',f'/api/v1/admissions/{identifier}/stage',token=admin_token,body={'source_path':'../outside'}).status_code==400
    assert call(api.base,'POST',f'/api/v1/admissions/{identifier}/stage',token=admin_token,body={'source_path':'missing'}).status_code==404


def _make_package(api,name,body="print('ok')\n"):
    package=api.managed/'inbound'/name
    (package/'src').mkdir(parents=True,exist_ok=True)
    (package/'src'/'main.py').write_text(body,encoding='utf-8')
    (package/'README.md').write_text(name,encoding='utf-8')
    return tree_hash(package)


def test_admission_installer_round_trip(api,admin_token):
    content_hash=_make_package(api,'skill-demo')
    data={'asset_instance_id':'asset_demo','content_hash':content_hash,'transaction_id':'txn_demo_1'}
    admission=call(api.base,'POST','/api/v1/admissions/check',token=admin_token,body=data).json()
    url='/api/v1/admissions/'+admission['admission_id']
    assert call(api.base,'POST',url+'/stage',token=admin_token,body={'source_path':'skill-demo'}).status_code==409
    call(api.base,'POST',url+'/approve',token=admin_token,body={}).raise_for_status()

    staged=call(api.base,'POST',url+'/stage',token=admin_token,body={'source_path':'skill-demo'})
    assert staged.status_code==200,staged.text
    assert staged.json()['state']=='staged' and staged.json()['observed_content_hash']==content_hash
    assert not (api.managed/'installed'/'asset_demo').exists()

    committed=call(api.base,'POST',url+'/commit',token=admin_token,body={})
    assert committed.status_code==200,committed.text
    assert committed.json()['state']=='committed' and committed.json()['rollback_ref']=='first_install'
    assert (api.managed/'installed'/'asset_demo'/'src'/'main.py').is_file()
    # 重复 commit 幂等：不二次落盘，状态不变。
    assert call(api.base,'POST',url+'/commit',token=admin_token,body={}).json()['state']=='committed'

    verified=call(api.base,'POST',url+'/verify',token=admin_token,body={})
    assert verified.status_code==200,verified.text
    assert verified.json()['state']=='verified' and verified.json()['observed_content_hash']==content_hash
    assert call(api.base,'POST',url+'/reconcile',token=admin_token,body={}).json()['state']=='reconciled'

    # 已验证实例允许下一轮升级；旧版本先快照，回滚恢复旧内容。
    upgraded=_make_package(api,'skill-demo',body="print('v2')\n")
    second=call(api.base,'POST','/api/v1/admissions/check',token=admin_token,
        body={'asset_instance_id':'asset_demo','content_hash':upgraded,'transaction_id':'txn_demo_2'}).json()
    second_url='/api/v1/admissions/'+second['admission_id']
    call(api.base,'POST',second_url+'/approve',token=admin_token,body={}).raise_for_status()
    call(api.base,'POST',second_url+'/stage',token=admin_token,body={'source_path':'skill-demo'}).raise_for_status()
    # 安装中的实例互斥：进行中的事务没完结，新事务不得开始。
    assert call(api.base,'POST','/api/v1/admissions/check',token=admin_token,
        body={'asset_instance_id':'asset_demo','content_hash':upgraded,'transaction_id':'txn_demo_3'}).status_code==409
    assert call(api.base,'POST',second_url+'/commit',token=admin_token,body={}).json()['state']=='committed'
    assert call(api.base,'POST',second_url+'/verify',token=admin_token,body={}).json()['observed_content_hash']==upgraded
    rolled=call(api.base,'POST',second_url+'/rollback',token=admin_token,body={})
    assert rolled.status_code==200,rolled.text
    assert rolled.json()['state']=='rolled_back' and 'restored' in rolled.json()['failure_reason']
    assert tree_hash(api.managed/'installed'/'asset_demo')==content_hash


def test_admission_content_drift_fails_without_installing(api,admin_token):
    content_hash=_make_package(api,'skill-drift')
    data={'asset_instance_id':'asset_drift','content_hash':content_hash,'transaction_id':'txn_drift_1'}
    admission=call(api.base,'POST','/api/v1/admissions/check',token=admin_token,body=data).json()
    url='/api/v1/admissions/'+admission['admission_id']
    call(api.base,'POST',url+'/approve',token=admin_token,body={}).raise_for_status()
    # 审批通过后改写 inbound 内容再 stage：暂存哈希与声明不一致，直接失败。
    _make_package(api,'skill-drift',body="print('tampered')\n")
    failed=call(api.base,'POST',url+'/stage',token=admin_token,body={'source_path':'skill-drift'})
    assert failed.status_code==200,failed.text
    assert failed.json()['state']=='failed' and 'content_drift' in failed.json()['failure_reason']
    assert not (api.managed/'installed'/'asset_drift').exists()
    # 失败后不能继续安装；回滚只清理暂存。
    assert call(api.base,'POST',url+'/commit',token=admin_token,body={}).status_code==409
    rolled=call(api.base,'POST',url+'/rollback',token=admin_token,body={})
    assert rolled.json()['state']=='rolled_back' and 'noop' in rolled.json()['failure_reason']
    assert not (api.managed/'staging'/'txn_drift_1').exists()


def test_admission_verify_mismatch_marks_failed_and_rolls_back(api,admin_token):
    content_hash=_make_package(api,'skill-tamper')
    data={'asset_instance_id':'asset_tamper','content_hash':content_hash,'transaction_id':'txn_tamper_1'}
    admission=call(api.base,'POST','/api/v1/admissions/check',token=admin_token,body=data).json()
    url='/api/v1/admissions/'+admission['admission_id']
    call(api.base,'POST',url+'/approve',token=admin_token,body={}).raise_for_status()
    call(api.base,'POST',url+'/stage',token=admin_token,body={'source_path':'skill-tamper'}).raise_for_status()
    call(api.base,'POST',url+'/commit',token=admin_token,body={}).raise_for_status()
    # 落盘后被外部改写：verify 必须发现不一致而不是记录为已验证。
    (api.managed/'installed'/'asset_tamper'/'src'/'main.py').write_text('tampered',encoding='utf-8')
    failed=call(api.base,'POST',url+'/verify',token=admin_token,body={})
    assert failed.status_code==200,failed.text
    assert failed.json()['state']=='failed' and 'installed_content_mismatch' in failed.json()['failure_reason']
    rolled=call(api.base,'POST',url+'/rollback',token=admin_token,body={})
    assert rolled.json()['state']=='rolled_back' and 'removed' in rolled.json()['failure_reason']
    assert not (api.managed/'installed'/'asset_tamper').exists()
    history=api.module.governance_service.repo.history('admissions',admission['admission_id'])
    assert [h['to_state'] for h in history]==['approved','staged','committed','failed','rolled_back']
    assert all(h['actor_id'].startswith('user_') for h in history)


def test_incident_requires_real_retest_and_records_actor(api,admin_token):
    response=call(api.base,'POST','/api/v1/incidents',token=admin_token,body={'title':'Investigation','severity':'high'})
    assert response.status_code==200,response.text
    identifier=response.json()['incident_id'];url='/api/v1/incidents/'+identifier
    assert call(api.base,'PATCH',url,token=admin_token,body={'status':'closed'}).status_code==409
    for status in ['investigating','confirmed','mitigating','verifying']:
        r=call(api.base,'PATCH',url,token=admin_token,body={'status':status});assert r.status_code==200,r.text
    assert call(api.base,'PATCH',url,token=admin_token,body={'status':'closed','retest_passed':True}).status_code==409
    from storage.repositories import DetectorRunRepository
    from adapters.detectors import RawOutput
    repo=DetectorRunRepository(api.module.storage)
    from adapters.detectors import NormalizedFinding
    from domain import Severity
    original=repo.create_run(detector_id='test',detector_version='1',target_ref='fixture',mode='static',timeout_seconds=10)
    repo.record_success(run_id=original,raw=RawOutput(report={},media_type='application/json',sha256='b'*64,byte_length=2),
        findings=[NormalizedFinding(rule_id='test-risk',title='Known test finding',severity=Severity.HIGH,message='test',fingerprint='f'*64,detector_id='test',detector_version='1')])
    with api.module.storage.connection() as connection:
        finding=connection.execute('SELECT finding_id FROM detector_run_findings WHERE detector_run_id=?',(original,)).fetchone()[0]
    call(api.base,'POST',url+'/evidence',token=admin_token,body={'evidence_kind':'finding','evidence_id':finding}).raise_for_status()
    run=repo.create_run(detector_id='test',detector_version='1',target_ref='fixture',mode='static',timeout_seconds=10)
    repo.record_success(run_id=run,raw=RawOutput(report={},media_type='application/json',sha256='a'*64,byte_length=2),findings=[])
    r=call(api.base,'POST',url+'/evidence',token=admin_token,body={'evidence_kind':'retest_run','evidence_id':run})
    assert r.status_code==200,r.text
    assert call(api.base,'PATCH',url,token=admin_token,body={'status':'closed'}).status_code==200
    assert call(api.base,'PATCH',url,token=admin_token,body={'status':'reopened'}).json()['closed_at'] is None
    history=api.module.governance_service.repo.history('incidents',identifier)
    assert len(history)==6 and all(h['actor_id'].startswith('user_') for h in history)


def test_viewer_cannot_mutate_governance(api,admin_token):
    call(api.base,'POST','/api/users',token=admin_token,body={'username':'viewer','password':'long-viewer-pass','role':'viewer'}).raise_for_status()
    token=call(api.base,'POST','/api/session',body={'username':'viewer','password':'long-viewer-pass'}).json()['token']
    assert call(api.base,'GET','/api/v1/incidents',token=token).status_code==200
    assert call(api.base,'POST','/api/v1/incidents',token=token,body={'title':'forbidden'}).status_code==403
    assert call(api.base,'GET','/api/v1/policies/versions',token=token).status_code==200
    assert call(api.base,'POST','/api/v1/policies/versions',token=token,
        body={'policy_version':'policy-x','rules':[{'rule_id':'r','action':'allow','reason':'x'}]}).status_code==403


def test_policy_versions_are_activated_atomically(api,admin_token):
    # 迁移播种的默认版本处于 active，求值记录真实版本号与命中规则。
    active=call(api.base,'GET','/api/v1/policies/active',token=admin_token).json()['active']
    assert active['policy_version']=='policy-v1' and active['status']=='active'
    risk=call(api.base,'POST','/api/v1/risk-assessments',token=admin_token,body={'exposure':{'privileged':True}}).json()
    decision=call(api.base,'POST','/api/v1/policies/evaluate',token=admin_token,
        body={'assessment_id':risk['assessment_id'],'subject_kind':'test','subject_id':'s'}).json()
    assert decision['policy_version']=='policy-v1'
    assert decision['reason'].startswith('confirm-exposed')

    # 新版本先是 draft，不影响当前求值。
    strict={'policy_version':'policy-strict','rules':[
        {'rule_id':'audit-everything','action':'audit','reason':'log all activity'},
        {'rule_id':'allow-clean','action':'allow','reason':'no dimension observed','peak_at_most':0}]}
    created=call(api.base,'POST','/api/v1/policies/versions',token=admin_token,body=strict)
    assert created.status_code==200,created.text
    assert created.json()['status']=='draft' and created.json()['created_by'].startswith('user_')
    again=call(api.base,'POST','/api/v1/policies/evaluate',token=admin_token,
        body={'assessment_id':risk['assessment_id'],'subject_kind':'test','subject_id':'s'}).json()
    assert again['policy_version']=='policy-v1'

    activated=call(api.base,'POST','/api/v1/policies/versions/policy-strict/activate',token=admin_token,body={})
    assert activated.status_code==200,activated.text
    assert activated.json()['status']=='active' and activated.json()['activated_at']
    after=call(api.base,'POST','/api/v1/policies/evaluate',token=admin_token,
        body={'assessment_id':risk['assessment_id'],'subject_kind':'test','subject_id':'s'}).json()
    assert after['policy_version']=='policy-strict' and after['action']=='audit'
    retired=call(api.base,'GET','/api/v1/policies/active',token=admin_token).json()['active']
    assert retired['policy_version']=='policy-strict'
    versions={item['policy_version']:item for item in call(api.base,'GET','/api/v1/policies/versions',token=admin_token).json()['items']}
    assert versions['policy-v1']['status']=='retired' and versions['policy-v1']['retired_at']
    # 已停用版本不能再次激活；重复激活当前版本是幂等的。
    assert call(api.base,'POST','/api/v1/policies/versions/policy-v1/activate',token=admin_token,body={}).status_code==409
    assert call(api.base,'POST','/api/v1/policies/versions/policy-strict/activate',token=admin_token,body={}).json()['status']=='active'
    history=api.module.governance_service.repo.history('policy_versions','policy-strict')
    assert [h['to_state'] for h in history]==['active']
    history=api.module.governance_service.repo.history('policy_versions','policy-v1')
    assert [h['to_state'] for h in history]==['retired']


def test_zero_risk_falls_through_to_allow_rule(api,admin_token):
    clean=call(api.base,'POST','/api/v1/risk-assessments',token=admin_token,body={}).json()
    assert clean['intrinsic_risk']==0 and clean['runtime_risk']==0 and clean['exposure_risk']==0
    decision=call(api.base,'POST','/api/v1/policies/evaluate',token=admin_token,
        body={'assessment_id':clean['assessment_id'],'subject_kind':'test','subject_id':'s'}).json()
    assert decision['action']=='allow' and decision['reason'].startswith('allow-clean')


def test_policy_version_input_is_validated(api,admin_token):
    assert call(api.base,'POST','/api/v1/policies/versions',token=admin_token,
        body={'policy_version':'p','rules':[]}).status_code==400
    assert call(api.base,'POST','/api/v1/policies/versions',token=admin_token,
        body={'policy_version':'p','rules':[{'rule_id':'r','action':'allow','reason':'x'},{'rule_id':'r','action':'block','reason':'y'}]}).status_code==400
    assert call(api.base,'POST','/api/v1/policies/versions',token=admin_token,
        body={'policy_version':'p','rules':[{'rule_id':'r','action':'sometimes','reason':'x'}]}).status_code==400
    assert call(api.base,'POST','/api/v1/policies/versions/nope/activate',token=admin_token,body={}).status_code==404


def test_evaluate_without_active_policy_is_refused(api,admin_token):
    risk=call(api.base,'POST','/api/v1/risk-assessments',token=admin_token,body={'exposure':{'privileged':True}}).json()
    with api.module.storage.connection() as c:
        c.execute("UPDATE policy_versions SET status='retired', retired_at='2026-11-12T00:00:00+00:00'")
    refused=call(api.base,'POST','/api/v1/policies/evaluate',token=admin_token,
        body={'assessment_id':risk['assessment_id'],'subject_kind':'test','subject_id':'s'})
    assert refused.status_code==500 and refused.json()['error']['code']=='no_active_policy'
