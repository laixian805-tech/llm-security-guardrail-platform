"""Endpoint transport guardrails for per-device credentials."""

from __future__ import annotations

from urllib.parse import urlsplit


def validate_device_upload_url(url: str) -> None:
    parsed = urlsplit(url)
    if parsed.scheme == "https":
        return
    if parsed.scheme == "http" and parsed.hostname in {
        "127.0.0.1", "::1", "localhost",
    }:
        return
    raise ValueError("device credentials require HTTPS or loopback-only HTTP")
