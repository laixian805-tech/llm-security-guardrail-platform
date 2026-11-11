"""治理 API：只读控制台权限与操作员写权限分离；设备不冒充分析员。"""
from domain import Permission,Admission,Incident,PolicyDecision,RiskAssessment
from services.ingestion_service import IngestError


def route(handler,method,parsed,governance,approval):
    path=parsed.path
    if path=='/api/v1/approval-requests' and method=='POST':
        result=approval.create(handler._device.device_id,handler._body())
    elif path.startswith('/api/v1/approval-requests/') and method=='GET':
        result=approval.get(path.rsplit('/',1)[1],device_id=handler._device.device_id)
    elif path=='/api/v1/approvals' and method=='GET':
        handler._send(200,{'approvals':[r.model_dump(mode='json') for r in approval.list()]});return True
    elif path.startswith('/api/v1/approvals/') and method=='POST':
        handler._user and handler._user.can(Permission.GOVERN) or _forbidden()
        result=approval.resolve(path.rsplit('/',1)[1],handler._body(),handler._actor().user_id)
    elif path=='/api/v1/risk-assessments' and method=='POST':
        result=governance.risk(handler._body())
    elif path=='/api/v1/policies/evaluate' and method=='POST':
        result=governance.evaluate(handler._body())
    elif path=='/api/v1/admissions/check' and method=='POST':
        result=governance.check_admission(handler._body())
    elif path.startswith('/api/v1/admissions/') and method=='POST':
        pieces=path.split('/')
        if len(pieces)!=6:return False
        result=governance.admission_transition(pieces[4],pieces[5],handler._body(),handler._actor().user_id)
    elif path=='/api/v1/incidents' and method=='POST':
        result=governance.create_incident(handler._body())
    elif path.startswith('/api/v1/incidents/') and method in ('PATCH','POST'):
        pieces=path.split('/')
        if len(pieces)==6 and pieces[5]=='evidence' and method=='POST':
            result=governance.add_evidence(pieces[4],handler._body())
        elif len(pieces)==5 and method=='PATCH':
            result=governance.incident_transition(pieces[4],handler._body(),handler._actor().user_id)
        else:return False
    elif path in ('/api/v1/risk-assessments','/api/v1/policy-decisions','/api/v1/admissions','/api/v1/incidents') and method=='GET':
        model={'risk-assessments':RiskAssessment,'policy-decisions':PolicyDecision,'admissions':Admission,'incidents':Incident}[path.rsplit('/',1)[1]]
        handler._send(200,{'items':[r.model_dump(mode='json') for r in governance.repo.list(model)]});return True
    else:return False
    handler._send(200,{**result.model_dump(mode='json'),'request_id':handler._request_id})
    return True


def _forbidden():
    from services.auth_service import AuthError
    raise AuthError('forbidden','govern permission required')
