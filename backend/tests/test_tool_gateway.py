from app.schemas.security import ToolDecision
from app.tools.gateway import CallerContext, ToolGateway, default_tool_catalog


def test_public_calculator_call_is_allowed() -> None:
    gateway = ToolGateway(default_tool_catalog())
    context = CallerContext(caller_role="public", user_id="student")

    verdict = gateway.authorize(
        "calculator",
        {"expression": "2 + 2 * 3"},
        context,
    )

    assert verdict.decision == ToolDecision.ALLOW
    assert verdict.args_check == "pass"
    assert verdict.permission_check == "pass"


def test_admin_export_data_is_blocked_for_public_caller() -> None:
    gateway = ToolGateway(default_tool_catalog())
    context = CallerContext(caller_role="public", user_id="student")

    verdict = gateway.authorize(
        "export_data",
        {"scope": "reports", "format": "json"},
        context,
    )

    assert verdict.decision == ToolDecision.BLOCK
    assert verdict.permission_check == "block"
    assert "admin" in verdict.reason


def test_search_kb_blocks_bulk_wildcard_query() -> None:
    gateway = ToolGateway(default_tool_catalog())
    context = CallerContext(caller_role="public", user_id="student")

    verdict = gateway.authorize(
        "search_kb",
        {"query": "*:*", "limit": 100},
        context,
    )

    assert verdict.decision == ToolDecision.BLOCK
    assert verdict.args_check == "block"
    assert "dangerous argument pattern" in verdict.reason


def test_tool_gateway_enforces_manifest_enum_and_type_constraints() -> None:
    gateway = ToolGateway(default_tool_catalog())
    context = CallerContext(caller_role="admin", user_id="admin")

    invalid_enum = gateway.authorize(
        "export_data",
        {"scope": "public_reports", "format": "json"},
        context,
    )
    invalid_type = gateway.authorize(
        "search_kb",
        {"query": "policy", "limit": "5"},
        context,
    )

    assert invalid_enum.decision == ToolDecision.BLOCK
    assert "scope" in invalid_enum.reason
    assert "one of" in invalid_enum.reason
    assert invalid_type.decision == ToolDecision.BLOCK
    assert "limit" in invalid_type.reason
    assert "integer" in invalid_type.reason
