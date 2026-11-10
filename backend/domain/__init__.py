"""ASGP 领域契约。

本包只放纯数据契约，不做 I/O。领域服务负责状态变化和治理动作，
Detector 与 Collector 不得直接写 Asset 状态。
"""

from domain.asset import Asset, AssetInstance, AssetRelease
from domain.detector import (
    DetectorDescriptor,
    DetectorRun,
    RawReportRef,
)
from domain.enums import (
    ActivationState,
    AssetType,
    AttributionMethod,
    Confidence,
    DetectorMode,
    FindingStatus,
    HookCapability,
    InstallationState,
    ProbeStatus,
    ProviderRole,
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
    "AssetType",
    "AttributionMethod",
    "Confidence",
    "DetectorDescriptor",
    "DetectorMode",
    "DetectorRun",
    "EvidenceRef",
    "Finding",
    "FindingStatus",
    "HookCapability",
    "InstallationState",
    "ModelProviderProfile",
    "ProbeStatus",
    "ProviderRole",
    "RawReportRef",
    "RuntimeState",
    "RunStatus",
    "Severity",
    "WireApi",
    "WireProfile",
]
