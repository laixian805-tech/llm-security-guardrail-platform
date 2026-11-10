"""ASGP 领域契约。

本包只放纯数据契约，不做 I/O。领域服务负责状态变化和治理动作，
Detector 与 Collector 不得直接写 Asset 状态。
"""

from domain.asset import Asset, AssetInstance, AssetRelease
from domain.auth import (
    AuditEvent,
    ConsoleSession,
    ConsoleUser,
    DeviceIdentity,
    RetentionRule,
    permissions_for,
)
from domain.detector import (
    DetectorDescriptor,
    DetectorRun,
    RawReportRef,
)
from domain.enums import (
    ActivationState,
    ActorKind,
    AuditOutcome,
    AssetType,
    AttributionMethod,
    Confidence,
    ConsoleRole,
    DetectorMode,
    DeviceStatus,
    FindingStatus,
    HookCapability,
    InstallationState,
    Permission,
    ProbeStatus,
    ProviderRole,
    RetentionKind,
    RuntimeState,
    RunStatus,
    Severity,
    WireApi,
)
from domain.evidence import EvidenceRef
from domain.finding import Finding
from domain.provider import ModelProviderProfile, WireProfile

__all__ = [
    "ActivationState",
    "Asset",
    "AssetInstance",
    "AssetRelease",
    "ActorKind",
    "AuditEvent",
    "AuditOutcome",
    "AssetType",
    "AttributionMethod",
    "Confidence",
    "ConsoleRole",
    "ConsoleSession",
    "ConsoleUser",
    "DetectorDescriptor",
    "DetectorMode",
    "DetectorRun",
    "DeviceIdentity",
    "DeviceStatus",
    "EvidenceRef",
    "Finding",
    "FindingStatus",
    "HookCapability",
    "InstallationState",
    "ModelProviderProfile",
    "Permission",
    "ProbeStatus",
    "ProviderRole",
    "RetentionKind",
    "RetentionRule",
    "RawReportRef",
    "RuntimeState",
    "RunStatus",
    "Severity",
    "WireApi",
    "WireProfile",
    "permissions_for",
]
