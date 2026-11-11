from datetime import datetime,timezone
import pytest
from test_console_auth import api,admin_token,call,login
from services.governance_service import GovernanceService
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
    # A workflow state alone must not pretend actual stage/install/verify happened.
    assert call(api.base,'POST',f'/api/v1/admissions/{identifier}/stage',token=admin_token,body={}).status_code==409


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
