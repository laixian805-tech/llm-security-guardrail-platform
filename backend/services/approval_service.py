"""控制面审批：设备创建和查询自身请求，控制台授权操作员作出决定。"""
from datetime import datetime,timezone,timedelta
import uuid
from pydantic import Field
from domain.asset import StrictModel
from domain.approval import ApprovalRequest
from products.registry import ProductCatalog
from services.ingestion_service import IngestError,reject_secrets
from storage.repositories import DeviceIdentityRepository


class ApprovalInput(StrictModel):
    product: str = Field(min_length=1,max_length=100)
    product_version: str = Field(min_length=1,max_length=100)
    session_id: str = Field(min_length=1,max_length=160)
    tool_call_id: str = Field(min_length=1,max_length=160)
    tool_name: str = Field(min_length=1,max_length=100)
    params_sha256: str = Field(pattern='^[0-9a-f]{64}$')
    timeout_seconds: int = Field(default=15,ge=1,le=20)


class ApprovalService:
    def __init__(self,storage):self.storage=storage

    def create(self,device_id,body):
        reject_secrets(body);value=ApprovalInput.model_validate(body)
        try:descriptor=ProductCatalog().descriptor(value.product)
        except KeyError:raise IngestError('unsupported_product') from None
        if descriptor.product_version!=value.product_version:raise IngestError('approval_product_version_unverified',409)
        device=DeviceIdentityRepository(self.storage).get(device_id)
        if not device or not device['host_id']:raise IngestError('host_unbound',409)
        now=datetime.now(timezone.utc);identifier='approval_'+uuid.uuid4().hex
        with self.storage._lock,self.storage.connection() as c:
            c.execute("INSERT OR IGNORE INTO approval_requests VALUES (?,?,?,?,?,?,?,?,?,'pending',?,?,NULL,NULL)",
                (identifier,device_id,device['host_id'],value.product,value.product_version,value.session_id,value.tool_call_id,value.tool_name,value.params_sha256,
                 now.isoformat(),(now+timedelta(seconds=value.timeout_seconds)).isoformat()))
            row=c.execute('SELECT * FROM approval_requests WHERE device_id=? AND product=? AND session_id=? AND tool_call_id=? AND params_sha256=?',
                (device_id,value.product,value.session_id,value.tool_call_id,value.params_sha256)).fetchone()
        return self.get(row['approval_id'],device_id=device_id)

    def _expire(self,c,now):
        c.execute("UPDATE approval_requests SET state='expired',resolved_at=? WHERE state='pending' AND expires_at<=?",(now,now))

    def get(self,identifier,device_id=None):
        with self.storage._lock,self.storage.connection() as c:
            self._expire(c,datetime.now(timezone.utc).isoformat())
            row=c.execute('SELECT * FROM approval_requests WHERE approval_id=?',(identifier,)).fetchone()
        if not row or (device_id is not None and row['device_id']!=device_id):raise IngestError('unknown_approval',404)
        return ApprovalRequest.model_validate(dict(row))

    def list(self):
        with self.storage._lock,self.storage.connection() as c:
            self._expire(c,datetime.now(timezone.utc).isoformat())
            return [ApprovalRequest.model_validate(dict(r)) for r in c.execute('SELECT * FROM approval_requests ORDER BY requested_at DESC LIMIT 100')]

    def resolve(self,identifier,body,actor_id):
        if set(body)!={'decision','params_sha256'} or body['decision'] not in ['approved','denied']:raise IngestError('invalid_approval_resolution')
        with self.storage._lock,self.storage.connection() as c:
            now=datetime.now(timezone.utc).isoformat();self._expire(c,now)
            row=c.execute('SELECT * FROM approval_requests WHERE approval_id=?',(identifier,)).fetchone()
            if not row:raise IngestError('unknown_approval',404)
            if row['params_sha256']!=body['params_sha256']:raise IngestError('approval_digest_mismatch',409)
            if row['state']==body['decision']:return ApprovalRequest.model_validate(dict(row))
            if row['state']!='pending':raise IngestError('approval_already_final',409)
            c.execute("UPDATE approval_requests SET state=?,resolved_at=?,resolved_by=? WHERE approval_id=? AND state='pending'",(body['decision'],now,actor_id,identifier))
        return self.get(identifier)
