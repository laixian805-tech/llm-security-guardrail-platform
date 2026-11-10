"""扫描服务：编排检测器执行、归一化和持久化。

这是唯一允许把 DetectorAdapter 输出写进存储的路径。检测器本身不写 Asset
状态、不创建 Incident；失败与 clean 在这里就分开记录。
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

from adapters.detectors import DetectorError, ScanRequest
from domain import RunStatus
from detectors.registry import DetectorCatalog
from storage.repositories import DetectorRunRepository, Storage


class ScanService:
    def __init__(self, *, storage: Storage, catalog: DetectorCatalog) -> None:
        self._runs = DetectorRunRepository(storage)
        self._catalog = catalog

    @property
    def runs(self) -> DetectorRunRepository:
        return self._runs

    def scan(self, *, detector_id: str, target: Path, target_ref: str,
             timeout_seconds: int = 300, idempotency_key: str | None = None,
             options: dict[str, Any] | None = None) -> dict[str, Any]:
        adapter = self._catalog.get(detector_id)
        descriptor = adapter.descriptor()

        if idempotency_key:
            existing = self._runs.find_by_idempotency_key(idempotency_key)
            if existing is not None:
                return {"detector_run_id": existing["detector_run_id"],
                        "status": existing["status"],
                        "finding_count": existing["finding_count"],
                        "deduplicated": True}

        run_id = self._runs.create_run(
            detector_id=detector_id,
            detector_version=descriptor.version,
            target_ref=target_ref,
            mode=descriptor.mode.value,
            timeout_seconds=timeout_seconds,
            idempotency_key=idempotency_key,
        )

        try:
            raw = adapter.scan(ScanRequest(
                target=target,
                target_ref=target_ref,
                timeout_seconds=timeout_seconds,
                options=options or {},
            ))
            findings = [
                replace(item, detector_id=detector_id, detector_version=descriptor.version)
                for item in adapter.normalize(raw)
            ]
        except DetectorError as exc:
            self._runs.record_failure(run_id=run_id, status=exc.run_status, error=exc.detail)
            raise

        result = self._runs.record_success(run_id=run_id, raw=raw, findings=findings)
        result["deduplicated"] = False
        result["detector_id"] = detector_id
        result["detector_version"] = descriptor.version
        result["target_ref"] = target_ref
        return result

    def import_report(self, *, detector_id: str, target_ref: str, report: Any,
                      idempotency_key: str | None = None) -> dict[str, Any]:
        """导入 SARIF 2.1.0 或扫描器 JSON，不执行子进程。

        导入的报告可以来自未注册的来源，此时用合成描述符记录身份，不假装
        知道引擎版本。
        """
        from adapters.detectors import RawOutput
        from adapters.detectors.normalize import normalize_report
        from domain import DetectorDescriptor, DetectorMode

        try:
            descriptor = self._catalog.get(detector_id).descriptor()
        except KeyError:
            descriptor = DetectorDescriptor(
                detector_id=detector_id,
                version="unknown",
                upstream_source="imported",
                license_id="unknown",
                input_types=["sarif", "json"],
                mode=DetectorMode.STATIC,
                boundary="外部导入的报告，未在本机执行",
            )

        if idempotency_key:
            existing = self._runs.find_by_idempotency_key(idempotency_key)
            if existing is not None:
                return {"detector_run_id": existing["detector_run_id"],
                        "status": existing["status"],
                        "finding_count": existing["finding_count"],
                        "deduplicated": True}

        import hashlib
        import json as _json

        payload = _json.dumps(report, ensure_ascii=False, sort_keys=True).encode("utf-8")
        raw = RawOutput(
            report=report,
            media_type="application/json",
            sha256=hashlib.sha256(payload).hexdigest(),
            byte_length=len(payload),
        )
        findings = [
            replace(item, detector_id=detector_id, detector_version=descriptor.version)
            for item in normalize_report(report)
        ]

        run_id = self._runs.create_run(
            detector_id=detector_id,
            detector_version=descriptor.version,
            target_ref=target_ref,
            mode=descriptor.mode.value,
            timeout_seconds=1,
            idempotency_key=idempotency_key,
        )
        result = self._runs.record_success(run_id=run_id, raw=raw, findings=findings)
        result["deduplicated"] = False
        result["detector_id"] = detector_id
        result["detector_version"] = descriptor.version
        result["target_ref"] = target_ref
        return result
