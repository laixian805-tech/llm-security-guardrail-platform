"""受控异步遥测批量入库队列（带同步鉴权、防背压过载与事件总线通知）。"""

from __future__ import annotations

import queue
import threading
import uuid
from typing import Any

from services.ingestion_service import IngestError, IngestionService
from services.notification_hub import NotificationHub


class AsyncIngestionWorker:
    """在校验设备身份和参数合规性后异步缓冲 batch 入库，平滑突发流量。"""

    def __init__(
        self,
        ingestion: IngestionService,
        hub: NotificationHub | None = None,
        *,
        maxsize: int = 256,
    ) -> None:
        self._ingestion = ingestion
        self._hub = hub
        self._queue: queue.Queue[tuple[str, str, dict[str, Any]] | None] = queue.Queue(maxsize=maxsize)
        self._lock = threading.Lock()
        self._processed = 0
        self._failed = 0
        self._stop = threading.Event()
        self._worker = threading.Thread(target=self._loop, daemon=True, name="asgp-async-ingest")
        self._worker.start()

    def enqueue(self, device_id: str, body: dict[str, Any]) -> dict[str, Any]:
        # 同步前置校验：主机绑定、批大小、秘密字段与时间格式必须立即 fail-closed，绝不先收后丢。
        self._ingestion.identity(device_id)
        rows = body.get("events") if isinstance(body, dict) else None
        if not isinstance(rows, list) or not 1 <= len(rows) <= 500:
            raise IngestError("invalid_batch_size")
        from services.ingestion_service import reject_secrets
        reject_secrets(body)
        task_id = "ingest_" + uuid.uuid4().hex[:16]
        try:
            self._queue.put_nowait((task_id, device_id, body))
        except queue.Full:
            raise IngestError("async_queue_full", 429) from None
        return {
            "accepted": True,
            "task_id": task_id,
            "queued_events": len(rows),
            "queue_depth": self._queue.qsize(),
        }

    def flush(self, timeout: float = 5.0) -> bool:
        import time
        deadline = time.monotonic() + timeout
        while self._queue.unfinished_tasks > 0:
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.01)
        return True

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {
                "queue_depth": self._queue.qsize(),
                "processed_batches": self._processed,
                "failed_batches": self._failed,
            }

    def stop(self) -> None:
        self._stop.set()
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            pass

    def _loop(self) -> None:
        while not self._stop.is_set():
            item = self._queue.get()
            if item is None:
                self._queue.task_done()
                break
            task_id, device_id, body = item
            try:
                res = self._ingestion.batch(device_id, body)
                with self._lock:
                    self._processed += 1
                if self._hub is not None:
                    self._hub.publish(
                        "ingestion.batch",
                        {"task_id": task_id, "device_id": device_id, **res},
                    )
            except Exception:
                with self._lock:
                    self._failed += 1
            finally:
                self._queue.task_done()
