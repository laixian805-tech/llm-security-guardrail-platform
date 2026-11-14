"""控制面实时事件总线：SSE 推流、审批阻塞长轮询与可选 HMAC Webhook 通知。"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import queue
import socket
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any


def _is_safe_webhook_url(url: str) -> bool:
    """默认阻断私网/回环 Webhook 目标以防 SSRF；测试显式设 ASGP_WEBHOOK_ALLOW_LOCAL=1 时放行。"""
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError:
        return False
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False
    if os.environ.get("ASGP_WEBHOOK_ALLOW_LOCAL") == "1":
        return True
    try:
        infos = socket.getaddrinfo(parsed.hostname, None)
    except OSError:
        return False
    for _, _, _, _, sockaddr in infos:
        try:
            ip = ipaddress.ip_address(sockaddr[0].split("%")[0])
        except ValueError:
            return False
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            return False
    return True


class NotificationHub:
    """线程安全的进程内事件通知中心。"""

    def __init__(self, *, max_queue_size: int = 128) -> None:
        self._max_queue_size = max_queue_size
        self._lock = threading.Lock()
        self._next_id = 1
        self._subscribers: dict[int, tuple[str, queue.Queue[dict[str, Any]]]] = {}
        self._approval_waiters: dict[str, threading.Condition] = {}
        self._latest_approvals: dict[str, dict[str, Any]] = {}

    def subscribe(self, topic_prefix: str = "") -> tuple[int, queue.Queue[dict[str, Any]]]:
        q: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=self._max_queue_size)
        with self._lock:
            sub_id = self._next_id
            self._next_id += 1
            self._subscribers[sub_id] = (topic_prefix, q)
        return sub_id, q

    def unsubscribe(self, sub_id: int) -> None:
        with self._lock:
            self._subscribers.pop(sub_id, None)

    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subscribers)

    def publish(self, topic: str, payload: dict[str, Any]) -> int:
        event = {
            "topic": topic,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload": payload,
        }
        delivered = 0
        with self._lock:
            subscribers = list(self._subscribers.values())
            cond = None
            approval_id = payload.get("approval_id") if topic.startswith("approval.") else None
            if approval_id and topic == "approval.resolved":
                self._latest_approvals[approval_id] = dict(payload)
                cond = self._approval_waiters.get(approval_id)
        for prefix, q in subscribers:
            if prefix and not topic.startswith(prefix):
                continue
            try:
                q.put_nowait(event)
            except queue.Full:
                try:
                    q.get_nowait()
                except queue.Empty:
                    pass
                try:
                    q.put_nowait(event)
                except queue.Full:
                    continue
            delivered += 1
        if approval_id and cond is not None:
            with cond:
                cond.notify_all()
        if topic in ("approval.requested", "approval.resolved"):
            self._maybe_dispatch_webhook(event)
        return delivered

    def wait_approval(self, approval_id: str, timeout: float = 15.0) -> dict[str, Any] | None:
        deadline = time.monotonic() + max(0.05, min(timeout, 20.0))
        with self._lock:
            cached = self._latest_approvals.get(approval_id)
            if cached is not None:
                return cached
            cond = self._approval_waiters.setdefault(approval_id, threading.Condition())
        with cond:
            while True:
                with self._lock:
                    cached = self._latest_approvals.get(approval_id)
                if cached is not None:
                    return cached
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                cond.wait(timeout=remaining)

    def _maybe_dispatch_webhook(self, event: dict[str, Any]) -> None:
        url = (os.environ.get("ASGP_APPROVAL_WEBHOOK_URL") or "").strip()
        if not url or not _is_safe_webhook_url(url):
            return
        secret = (os.environ.get("ASGP_APPROVAL_WEBHOOK_SECRET") or "").encode("utf-8")
        body = json.dumps(event, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if secret:
            sig = hmac.new(secret, body, hashlib.sha256).hexdigest()
            headers["X-ASGP-Signature"] = f"sha256={sig}"

        def _send() -> None:
            try:
                req = urllib.request.Request(url, data=body, headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=2.5):
                    pass
            except Exception:
                pass

        threading.Thread(target=_send, daemon=True, name="asgp-webhook").start()
