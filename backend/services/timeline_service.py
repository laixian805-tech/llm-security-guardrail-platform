"""以稳定键分页，避免时间戳相同的事件重漏。"""
import base64
import json
from datetime import datetime
from domain.timeline import TimelineEntry, TimelineResponse
from products.registry import ProductCatalog
from services.ingestion_service import IngestError
from storage.execution_repositories import ExecutionRepository, IntentRepository, RuntimeEventRepository


class TimelineService:
    def __init__(self, storage):
        self.executions = ExecutionRepository(storage)
        self.intents = IntentRepository(storage)
        self.events = RuntimeEventRepository(storage)

    def get(self, execution_id, *, limit=100, cursor=None):
        execution = self.executions.get(execution_id)
        if not execution:
            raise IngestError("unknown_execution", 404)
        entries = []
        for kind, rows, key in [("intent", self.intents.list_for_execution(execution_id), "intent_id"),
                                 ("runtime_event", self.events.list_for_execution(execution_id), "event_id")]:
            for row in rows:
                row = dict(row)
                if kind == "runtime_event":
                    row["evidence_refs"] = json.loads(row["evidence_refs"])
                entries.append(TimelineEntry(kind=kind, id=row[key], occurred_at=row["occurred_at"], data=row))
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
            capability_verification=verification, entries=page, next_cursor=next_cursor).model_dump(mode="json")
