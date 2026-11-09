from __future__ import annotations

from app.agent_security.models import TIVerdict
from app.agent_security.store import AgentSecStore
from app.agent_security.threat_intel import extract_iocs
from app.agent_security.threat_intel import (
    normalize_ioc,
    parse_threatbook_payload,
    utc_budget_day,
)
from app.agent_security.transport import validate_device_upload_url


def test_normalize_ioc_only_accepts_public_ip_valid_hash_and_domain() -> None:
    assert normalize_ioc("83.2.103.14") == ("83.2.103.14", "ip")
    assert normalize_ioc("127.0.0.1") is None
    assert normalize_ioc("10.0.0.1") is None
    assert normalize_ioc("localhost") is None
    assert normalize_ioc("example.com") == ("example.com", "domain")
    assert normalize_ioc("a" * 64) == ("a" * 64, "sha256")
    assert normalize_ioc("/home/lab/.ssh/id_rsa") is None


def test_parse_ip_reputation_preserves_unknown_clean_and_malicious() -> None:
    malicious = parse_threatbook_payload("83.2.103.14", "ip", {
        "response_code": 0,
        "data": {"83.2.103.14": {
            "is_malicious": True, "severity": "high", "confidence_level": "high",
        }},
    })
    assert malicious == TIVerdict(provider="threatbook", verdict="malicious",
                                  confidence=0.9, cached=False)

    clean = parse_threatbook_payload("8.8.8.8", "ip", {
        "response_code": 0,
        "data": {"8.8.8.8": {
            "is_malicious": False, "severity": "info", "confidence_level": "low",
        }},
    })
    assert clean.verdict == "clean"
    assert clean.confidence == 0.35

    unknown = parse_threatbook_payload("83.2.103.14", "ip", {
        "response_code": -1, "verbose_msg": "Invalid API Key",
    })
    assert unknown.verdict == "unknown"
    assert unknown.verdict != "clean"


def test_domain_payload_is_parsed_when_provider_returns_a_result() -> None:
    verdict = parse_threatbook_payload("example.com", "domain", {
        "response_code": 0, "data": {"example.com": {"severity": "high"}},
    })
    assert verdict.verdict == "malicious"


def test_domain_lookup_stays_unknown_until_account_capability_is_enabled(monkeypatch) -> None:
    from app.agent_security.threat_intel import ThreatBookClient

    monkeypatch.delenv("THREATBOOK_DOMAIN_ENABLED", raising=False)
    monkeypatch.setattr("app.agent_security.threat_intel.urllib.request.urlopen",
                        lambda *_args, **_kwargs: (_ for _ in ()).throw(
                            AssertionError("disabled domain endpoint must not be called")))
    verdict = ThreatBookClient(api_key="test-key").lookup("example.com", "domain")
    assert verdict.verdict == "unknown"


def test_ioc_extraction_keeps_public_normalized_indicators_only() -> None:
    found = extract_iocs("fetch https://Bad.Example/path, connect 8.8.8.8 and 10.0.0.2")
    assert found == [("8.8.8.8", "ip"), ("bad.example", "domain")]


def test_lookup_records_live_result_and_cache_hit(tmp_path) -> None:
    from app.agent_security.ti import check_ioc

    class Client:
        domain_enabled = False

        def __init__(self):
            self.calls = 0

        def lookup(self, ioc, ioc_type):
            self.calls += 1
            return TIVerdict(verdict="malicious", confidence=0.95)

    store = AgentSecStore(tmp_path / "ioc.db")
    client = Client()
    first = check_ioc(store, "8.8.8.8", mode="shadow", client=client)
    second = check_ioc(store, "8.8.8.8", mode="shadow", client=client)
    queries = store.list_ioc_queries()

    assert first["cached"] is False
    assert second["cached"] is True
    assert client.calls == 1
    assert [(row["verdict"], row["cached"]) for row in reversed(queries)] == [
        ("malicious", False), ("malicious", True),
    ]


def test_disabled_domain_lookup_is_logged_without_spending_budget(tmp_path, monkeypatch) -> None:
    from app.agent_security.ti import check_ioc

    monkeypatch.delenv("THREATBOOK_DOMAIN_ENABLED", raising=False)
    store = AgentSecStore(tmp_path / "domain.db")
    result = check_ioc(store, "example.com", mode="shadow")

    assert result["verdict"] == "unknown"
    assert "not enabled" in result["reason"]
    assert store.get_state(f"ti_budget:{utc_budget_day()}", "0") == "0"
    query = store.list_ioc_queries()[0]
    assert query["ioc_type"] == "domain"
    assert query["cached"] is False


def test_device_tokens_are_rejected_over_plain_remote_http() -> None:
    validate_device_upload_url("http://127.0.0.1:8000/api/agent-security/events")
    validate_device_upload_url("https://security.example.com/api/agent-security/events")
    try:
        validate_device_upload_url("http://security.example.com/api/agent-security/events")
    except ValueError as exc:
        assert "HTTPS" in str(exc)
    else:
        raise AssertionError("remote HTTP must not carry endpoint tokens")
