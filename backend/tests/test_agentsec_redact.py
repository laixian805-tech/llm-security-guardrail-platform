from __future__ import annotations

from app.agent_security.redact import hash_value, redact_text, redact_value


def test_redacts_key_value_secrets() -> None:
    text = 'config: api_key=sk-live-1234567890 and token: "abcdef123456"'
    redacted = redact_text(text)
    assert "sk-live-1234567890" not in redacted
    assert "abcdef123456" not in redacted
    assert "***REDACTED***" in redacted


def test_redacts_bearer_and_aws_and_private_key() -> None:
    assert "Bearer" not in redact_text("Authorization: Bearer abcdef1234567890")
    assert "AKIA" not in redact_text("aws key AKIAIOSFODNN7EXAMPLE")
    assert "PRIVATE KEY" not in redact_text("-----BEGIN RSA PRIVATE KEY-----")


def test_redact_value_walks_nested_structures() -> None:
    payload = {"cmd": "export TOKEN=supersecretvalue", "nested": [{"password": "hunter2hunter2"}]}
    redacted = redact_value(payload)
    assert "supersecretvalue" not in redacted["cmd"]
    assert "hunter2hunter2" not in redacted["nested"][0]["password"]


def test_hash_value_is_stable_sha256() -> None:
    assert hash_value("x") == hash_value("x")
    assert len(hash_value("x")) == 64
    assert hash_value("x") != hash_value("y")
