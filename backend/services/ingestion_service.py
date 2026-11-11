"""设备摄入边界：权威主机身份、跨设备隔离、幂等与秘密拒收。"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from pydantic import AwareDatetime, Field, ValidationError

from domain import ExecutionOutcome, Intent, RuntimeEvent
from domain.asset import StrictModel
from storage.execution_repositories import (
    ExecutionConflict, ExecutionRepository, IntentRepository, RuntimeEventRepository,
)
from storage.repositories import DeviceIdentityRepository, Storage, now_iso
from products.registry import ProductCatalog
from domain import HookCapability, IntentDecision


class IngestError(Exception):
    def __init__(self, code: str, status: int = 400):
        self.code, self.status = code, status
        super().__init__(code)


class ExecutionInput(StrictModel):
    execution_id: str = Field(min_length=1, max_length=160)
    session_id: str = Field(min_length=1, max_length=160)
    product: str
    product_version: str = Field(min_length=1, max_length=100)
    started_at: AwareDatetime
    ended_at: AwareDatetime | None = None
    outcome: ExecutionOutcome = ExecutionOutcome.RUNNING
    asset_instance_id: str | None = None
    host_id: str | None = None
    device_id: str | None = None


SECRET = re.compile(r"sk-(?:ant-)?[A-Za-z0-9_-]{16,}|AKIA[A-Z0-9]{16}|-----BEGIN [A-Z ]*PRIVATE KEY|Bearer\s+\S{12,}", re.I)
SECRET_KEYS = {"authorization", "api_key", "apikey", "password", "secret", "access_token", "environment", "environ", "prompt", "tool_input", "transcript_path", "argv", "command_line"}


def reject_secrets(value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in SECRET_KEYS and item:
                raise IngestError("suspected_secret_parameter")
            reject_secrets(item)
    elif isinstance(value, list):
        for item in value:
            reject_secrets(item)
    elif isinstance(value, str) and SECRET.search(value):
        raise IngestError("suspected_secret_parameter")


class IngestionService:
    def __init__(self, storage: Storage):
        self.devices = DeviceIdentityRepository(storage)
        self.executions = ExecutionRepository(storage)
        self.intents = IntentRepository(storage)
        self.events = RuntimeEventRepository(storage)
        self.storage = storage

    def identity(self, device_id: str) -> dict:
        row = self.devices.get(device_id)
        if not row or not row["host_id"]:
            raise IngestError("host_unbound", 409)
        return row

    def owns(self, execution_id: str, device_id: str) -> dict:
        row = self.executions.get(execution_id)
        if not row:
            raise IngestError("unknown_execution", 404)
        device = self.identity(device_id)
        if row["device_id"] != device_id or row["host_id"] != device["host_id"]:
            raise IngestError("execution_id_conflict", 409)
        return row

    def execution(self, device_id: str, body: dict) -> dict:
        reject_secrets(body)
        data = ExecutionInput.model_validate(body)
        if data.product not in ("codex", "claude-code"):
            raise IngestError("unsupported_product")
        terminal = data.outcome in (ExecutionOutcome.COMPLETED, ExecutionOutcome.ABORTED, ExecutionOutcome.FAILED)
        if (data.outcome == ExecutionOutcome.RUNNING and data.ended_at is not None) or (terminal and data.ended_at is None):
            raise IngestError("invalid_execution_state")
        if data.ended_at and data.ended_at < data.started_at:
            raise IngestError("invalid_execution_time")
        device = self.identity(device_id)
        existing = self.executions.get(data.execution_id)
        if existing and (existing["product"] != data.product or existing["session_id"] != data.session_id):
            raise IngestError("execution_id_conflict", 409)
        args = data.model_dump(exclude={"host_id", "device_id"})
        args['started_at'] = data.started_at.astimezone(timezone.utc)
        if data.ended_at:
            args['ended_at'] = data.ended_at.astimezone(timezone.utc)
        try:
            return self.executions.upsert(**args, host_id=device["host_id"], device_id=device_id)
        except ExecutionConflict:
            raise IngestError("execution_id_conflict", 409) from None

    def intent(self, device_id: str, execution_id: str, body: dict) -> dict:
        reject_secrets(body)
        execution = self.owns(execution_id, device_id)
        now = now_iso()
        data = Intent.model_validate({**body, "execution_id": execution_id, "created_at": now})
        for dt in (data.occurred_at, data.ended_at):
            if dt and dt.tzinfo is None:
                raise IngestError("timezone_required")
        if data.decision is not IntentDecision.NOT_APPLICABLE:
            descriptor = ProductCatalog().descriptor(execution['product'])
            capability = descriptor.capability_for(data.hook_event_type)
            needed = HookCapability.CONFIRM if data.decision is IntentDecision.ASK else HookCapability.DENY if data.decision is IntentDecision.DENY else HookCapability.OBSERVE
            if descriptor.product_version != execution['product_version'] or not capability or needed not in capability.capabilities:
                raise IngestError('unsupported_decision')
        data.occurred_at = data.occurred_at.astimezone(timezone.utc)
        if data.ended_at:
            data.ended_at = data.ended_at.astimezone(timezone.utc)
        if data.parent_intent_id:
            raise IngestError("parent_intent_not_supported")
        with self.storage.connection() as conn:
            row = conn.execute("SELECT execution_id FROM intents WHERE intent_id=?", (data.intent_id,)).fetchone()
        if row and row["execution_id"] != execution_id:
            raise IngestError("intent_id_conflict", 409)
        return self.intents.record(**data.model_dump(exclude={"created_at"}))

    def batch(self, device_id: str, body: dict) -> dict:
        reject_secrets(body)
        device = self.identity(device_id)
        if set(body) - {"host_id", "collector_id", "events"}:
            raise IngestError("invalid_batch")
        rows = body.get("events")
        if not isinstance(rows, list) or not 1 <= len(rows) <= 500:
            raise IngestError("invalid_batch_size")
        events = []
        for item in rows:
            if not isinstance(item, dict):
                raise IngestError("invalid_event")
            data = RuntimeEvent.model_validate({**item, "host_id": device["host_id"], "device_id": device_id,
                "collector_id": body.get("collector_id", item.get("collector_id")), "received_at": now_iso()})
            if data.occurred_at.tzinfo is None:
                raise IngestError("timezone_required")
            if data.execution_id:
                self.owns(data.execution_id, device_id)
            events.append(data)
        return self.events.record_many(events)
