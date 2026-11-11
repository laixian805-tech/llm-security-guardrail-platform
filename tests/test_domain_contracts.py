"""领域契约测试：锁定 IMPLEMENTATION_PLAN.md P0 的契约边界。

这些测试保护的是"不能折叠的区分"：severity 与 confidence、Finding 与
Risk Assessment、运行失败与 clean、观察与阻断、候选供应商与默认路由。
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from domain import (
    Asset,
    AssetInstance,
    AssetRelease,
    ActivationState,
    Confidence,
    DetectorDescriptor,
    DetectorMode,
    DetectorRun,
    Execution,
    ExecutionOutcome,
    Finding,
    HookEventType,
    InstallationState,
    Intent,
    IntentDecision,
    ModelProviderProfile,
    ProbeStatus,
    ProviderRole,
    ProcessInfo,
    ResourceInfo,
    RunStatus,
    RuntimeEvent,
    Severity,
    WireApi,
    WireProfile,
)

NOW = datetime(2026, 11, 10, tzinfo=timezone.utc)


def make_finding(**overrides):
    payload = dict(
        finding_id="find_1",
        detector_run_id="run_1",
        detector_id="nvidia.skillspector",
        detector_version="2.12.0",
        rule_id="asgp.skill.prompt-injection",
        title="疑似提示注入",
        fingerprint="fp_1",
        created_at=NOW,
        updated_at=NOW,
    )
    payload.update(overrides)
    return Finding(**payload)


def make_run(**overrides):
    payload = dict(
        detector_run_id="run_1",
        detector_id="nvidia.skillspector",
        detector_version="2.12.0",
        target_ref="workspace/skills/example",
        mode=DetectorMode.STATIC,
        status=RunStatus.SUCCEEDED,
        started_at=NOW,
        finished_at=NOW,
        timeout_seconds=300,
        normalizer_version="1.0.0",
    )
    payload.update(overrides)
    return DetectorRun(**payload)


class TestFindingContract:
    def test_severity_and_confidence_are_independent(self):
        finding = make_finding(severity=Severity.HIGH, confidence=Confidence.LOW)
        assert finding.severity is Severity.HIGH
        assert finding.confidence is Confidence.LOW

    def test_unknown_severity_is_default_not_derived(self):
        # 不得从 upstream_risk_score 反推严重度。
        finding = make_finding(upstream_risk_score=9.9)
        assert finding.severity is Severity.UNKNOWN
        assert finding.confidence is Confidence.UNKNOWN

    def test_upstream_rule_id_is_preserved(self):
        finding = make_finding(upstream_rule_id="SKILLSPECTOR-042")
        assert finding.upstream_rule_id == "SKILLSPECTOR-042"

    def test_asset_linkage_is_optional(self):
        # 无法关联资产时留空，不用目标路径猜测填充。
        assert make_finding().asset_id is None
        assert make_finding(asset_id="asset_1").asset_id == "asset_1"

    def test_unknown_field_is_rejected(self):
        with pytest.raises(ValidationError):
            make_finding(risk_assessment="high")


class TestDetectorRunContract:
    @pytest.mark.parametrize(
        "status",
        [RunStatus.TIMED_OUT, RunStatus.FAILED, RunStatus.OUTPUT_LIMIT_EXCEEDED],
    )
    def test_failure_is_never_clean(self, status):
        run = make_run(status=status, error="boom")
        assert run.is_clean is False

    def test_success_without_findings_is_clean(self):
        assert make_run().is_clean is True

    def test_success_with_findings_is_not_clean(self):
        assert make_run(finding_count=3).is_clean is False

    def test_non_success_requires_error(self):
        with pytest.raises(ValidationError):
            make_run(status=RunStatus.FAILED, finished_at=NOW)

    def test_success_requires_finished_at(self):
        with pytest.raises(ValidationError):
            make_run(finished_at=None)

    def test_queued_allows_missing_error(self):
        run = make_run(status=RunStatus.QUEUED, finished_at=None)
        assert run.is_clean is False

    def test_model_usage_records_protocol_not_prompt(self):
        run = make_run(
            provider_profile_id="stepfun",
            model_id="step-5-preview",
            wire_api=WireApi.CHAT_COMPLETIONS,
            latency_ms=812,
        )
        assert run.wire_api is WireApi.CHAT_COMPLETIONS
        dumped = run.model_dump()
        assert "prompt" not in dumped
        assert "api_key" not in dumped

    def test_raw_report_is_a_reference(self):
        run = make_run(
            raw_report={
                "raw_report_id": "raw_1",
                "uri": "raw/run_1.json",
                "media_type": "application/json",
                "sha256": "0" * 64,
                "byte_length": 2048,
            }
        )
        assert run.raw_report.uri == "raw/run_1.json"


class TestProviderProfileContract:
    def test_candidate_is_not_routed_before_probe(self):
        with pytest.raises(ValidationError):
            ModelProviderProfile(
                provider_id="xunfei",
                name="讯飞星火",
                role=ProviderRole.CANDIDATE,
                selected=True,
            )

    def test_candidate_can_be_selected_after_probe(self):
        profile = ModelProviderProfile(
            provider_id="xunfei",
            name="讯飞星火",
            role=ProviderRole.CANDIDATE,
            selected=True,
            probe_status=ProbeStatus.PASSED,
        )
        assert profile.selected is True

    def test_contract_never_carries_secret_material(self):
        profile = ModelProviderProfile(
            provider_id="stepfun",
            name="StepFun",
            role=ProviderRole.PRIMARY,
            selected=True,
            probe_status=ProbeStatus.PASSED,
            scanner_profile=WireProfile(
                wire_api=WireApi.CHAT_COMPLETIONS,
                base_url="https://api.stepfun.com/v1",
                model="step-5-preview",
                source="codex_config",
                configured=True,
                secret_configured=True,
            ),
        )
        dumped = profile.model_dump()
        assert dumped["scanner_profile"]["secret_configured"] is True
        # 契约里不存在任何密钥字段。
        assert "secret" not in dumped["scanner_profile"]
        assert "authorization" not in dumped["scanner_profile"]

    def test_responses_and_chat_completions_are_separate_profiles(self):
        profile = ModelProviderProfile(
            provider_id="stepfun",
            name="StepFun",
            role=ProviderRole.PRIMARY,
            selected=True,
            probe_status=ProbeStatus.PASSED,
            codex_profile=WireProfile(
                wire_api=WireApi.RESPONSES,
                base_url="https://api.stepfun.com/step_plan/v1",
                source="codex_config",
            ),
            scanner_profile=WireProfile(
                wire_api=WireApi.CHAT_COMPLETIONS,
                base_url="https://api.stepfun.com/v1",
                model="step-5-preview",
                source="codex_config",
            ),
        )
        assert profile.codex_profile.wire_api is WireApi.RESPONSES
        assert profile.scanner_profile.wire_api is WireApi.CHAT_COMPLETIONS
        assert profile.codex_profile.base_url != profile.scanner_profile.base_url


class TestAssetIdentitySeparation:
    def test_logical_instance_and_release_are_distinct(self):
        asset = Asset(
            asset_id="asset_1",
            asset_type="skill",
            canonical_name="example-skill",
            product="claude-code",
            publisher="acme",
            created_at=NOW,
            updated_at=NOW,
        )
        release = AssetRelease(
            release_id="rel_1",
            asset_id=asset.asset_id,
            version="1.2.0",
            content_hash="a" * 64,
        )
        instances = [
            AssetInstance(
                instance_id=f"inst_{scope}",
                asset_id=asset.asset_id,
                host_id="host_1",
                product_scope=scope,
                installation_state=InstallationState.INSTALLED,
                activation_state=ActivationState.ENABLED,
                first_seen_at=NOW,
                last_seen_at=NOW,
            )
            for scope in ("claude-code", "codex")
        ]
        assert release.asset_id == instances[0].asset_id == instances[1].asset_id
        assert instances[0].instance_id != instances[1].instance_id
        assert instances[0].product_scope != instances[1].product_scope

    def test_three_states_are_independent(self):
        instance = AssetInstance(
            instance_id="inst_1",
            asset_id="asset_1",
            host_id="host_1",
            product_scope="claude-code",
            installation_state=InstallationState.INSTALLED,
            activation_state=ActivationState.DISABLED,
            runtime_state="idle",
            first_seen_at=NOW,
            last_seen_at=NOW,
        )
        assert instance.installation_state is InstallationState.INSTALLED
        assert instance.activation_state is ActivationState.DISABLED


class TestDetectorDescriptor:
    def test_llm_scanner_declares_its_dependency(self):
        descriptor = DetectorDescriptor(
            detector_id="aig-skill-scan",
            version="0.2.2",
            upstream_source="Tencent/AI-Infra-Guard",
            license_id="Apache-2.0",
            input_types=["skill_directory", "skill_md"],
            mode=DetectorMode.STATIC,
            llm_required=True,
            capabilities=["json"],
            boundary="调用配置的 LLM 服务，目标内容会发送给该服务",
        )
        assert descriptor.llm_required is True
        assert descriptor.boundary != ""


def make_execution(**overrides):
    payload = dict(
        execution_id="exec_1",
        host_id="host_1",
        device_id="dev_1",
        product="claude-code",
        product_version="2.0.0",
        session_id="sess_1",
        started_at=NOW,
        created_at=NOW,
        updated_at=NOW,
    )
    payload.update(overrides)
    return Execution(**payload)


def make_intent(**overrides):
    payload = dict(
        intent_id="intent_1",
        execution_id="exec_1",
        tool_name="Bash",
        hook_event_type=HookEventType.PRE_TOOL_USE,
        occurred_at=NOW,
        created_at=NOW,
    )
    payload.update(overrides)
    return Intent(**payload)


class TestExecution:
    def test_running_has_no_ended_at(self):
        with pytest.raises(ValidationError):
            make_execution(outcome=ExecutionOutcome.RUNNING, ended_at=NOW)

    def test_terminal_requires_ended_at(self):
        with pytest.raises(ValidationError):
            make_execution(outcome=ExecutionOutcome.COMPLETED)

    def test_ended_at_cannot_precede_started_at(self):
        from datetime import timedelta

        with pytest.raises(ValidationError):
            make_execution(
                outcome=ExecutionOutcome.COMPLETED,
                ended_at=NOW - timedelta(seconds=1),
            )

    def test_unknown_outcome_is_not_terminal(self):
        execution = make_execution(outcome=ExecutionOutcome.UNKNOWN)
        assert execution.is_terminal is False

    def test_execution_is_not_a_process(self):
        # 同一会话的多次工具调用共享一个 Execution；边界字段是会话而非进程。
        execution = make_execution()
        assert execution.session_id == "sess_1"
        assert not hasattr(execution, "pid")


class TestIntent:
    def test_pre_execution_event_carries_decision(self):
        intent = make_intent(decision=IntentDecision.DENY, decision_reason="策略禁止")
        assert intent.decision is IntentDecision.DENY

    def test_post_execution_event_cannot_carry_decision(self):
        # observe 模式下的观测事件一旦带决策语义，报告会把"看到了"呈现成"拦住了"。
        with pytest.raises(ValidationError):
            make_intent(
                hook_event_type=HookEventType.POST_TOOL_USE,
                decision=IntentDecision.DENY,
                decision_reason="策略禁止",
            )

    def test_session_events_cannot_carry_decision(self):
        for event in (HookEventType.SESSION_START, HookEventType.SESSION_END,
                      HookEventType.SYNTHETIC):
            with pytest.raises(ValidationError):
                make_intent(hook_event_type=event, decision=IntentDecision.ALLOW)

    def test_decision_reason_requires_decision(self):
        with pytest.raises(ValidationError):
            make_intent(decision=IntentDecision.NOT_APPLICABLE, decision_reason="没有决策")

    def test_params_sha256_must_be_hex_digest(self):
        with pytest.raises(ValidationError):
            make_intent(params_sha256="xyz")
        with pytest.raises(ValidationError):
            make_intent(params_sha256="A" * 64)
        intent = make_intent(params_sha256="a" * 64)
        assert intent.params_sha256 == "a" * 64

    def test_tool_input_never_enters_contract(self):
        fields = set(Intent.model_fields)
        for forbidden in ("tool_input", "prompt", "transcript_path", "environment",
                          "env", "command_line"):
            assert forbidden not in fields

    def test_params_summary_is_bounded(self):
        # 端侧脱敏后仍是任意结构，超出上限即拒绝而不是静默截断：
        # 截断会让摘要与 params_sha256 对不上。
        with pytest.raises(ValidationError):
            make_intent(params_summary="x" * 8193)
        assert len(make_intent(params_summary="x" * 8192).params_summary) == 8192


class TestRuntimeEvent:
    def test_observation_can_lack_execution_attribution(self):
        event = RuntimeEvent(
            event_id="evt_1",
            host_id="host_1",
            collector_id="linux-audit-v1",
            device_id="dev_1",
            event_type="process_exec",
            occurred_at=NOW,
            received_at=NOW,
        )
        assert event.execution_id is None
        assert event.intent_ref is None

    def test_intent_ref_is_a_hint_not_a_reference(self):
        # intent_ref 只是采集器提示，不是外键；权威关联是 P2 的 EventAttribution。
        event = RuntimeEvent(
            event_id="evt_1",
            host_id="host_1",
            collector_id="linux-audit-v1",
            device_id="dev_1",
            intent_ref="toolu_01ABC",
            event_type="file_access",
            occurred_at=NOW,
            received_at=NOW,
            process=ProcessInfo(pid=1, ppid=0, executable="/bin/sh"),
            resource=ResourceInfo(path="/etc/passwd"),
        )
        assert event.intent_ref == "toolu_01ABC"

    def test_contract_never_carries_prompt_or_command_line(self):
        fields = set(RuntimeEvent.model_fields) | set(ProcessInfo.model_fields) \
            | set(ResourceInfo.model_fields)
        for forbidden in ("prompt", "tool_input", "command_line", "argv", "environ",
                          "secret", "authorization", "api_key"):
            assert forbidden not in fields
        # 进程可执行文件路径是允许的定位信息，命令行不是。
        assert "executable" in ProcessInfo.model_fields

    def test_resource_port_is_validated(self):
        with pytest.raises(ValidationError):
            ResourceInfo(port=70000)
        with pytest.raises(ValidationError):
            ProcessInfo(pid=-1)
