"""Pre-install and pre-enable admission checks for agent assets.

The scanner produces observations; this module is the small, explicit gate
that callers can put on an install or enable path.  It deliberately fails
closed when the caller has not supplied enough evidence to identify the
asset, verify its content, or establish that the asset is eligible for use.

The gate does not turn a static finding into ``confirmed_malicious``.  It
returns an operational allow/block decision and a list of explainable checks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from .scanner import Registry, sha256_path


BLOCKED_ASSESSMENTS = frozenset({
    "high_risk_candidate",
    "confirmed_malicious",
})

BLOCKED_CARRIERS = frozenset({
    "marketplace_cache",
    "codex_plugin_cache",
    "vendor_dependency",
    "dependency_or_vendor_content",
})


@dataclass(frozen=True)
class AdmissionCheck:
    """One deterministic input to an admission decision."""

    name: str
    passed: bool
    reason: str


@dataclass(frozen=True)
class AdmissionDecision:
    """Operational result of an install/enable admission evaluation."""

    allowed: bool
    action: str
    reason: str
    checks: tuple[AdmissionCheck, ...] = field(default_factory=tuple)
    kind: str = ""
    name: str = ""
    path: str = ""
    sha256: str = ""

    @property
    def blocked(self) -> bool:
        return not self.allowed

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "action": self.action,
            "reason": self.reason,
            "checks": [
                {"name": check.name, "passed": check.passed,
                 "reason": check.reason}
                for check in self.checks
            ],
            "kind": self.kind,
            "name": self.name,
            "path": self.path,
            "sha256": self.sha256,
        }


def _check(name: str, passed: bool, reason: str) -> AdmissionCheck:
    return AdmissionCheck(name=name, passed=passed, reason=reason)


def _bool_value(value: Any) -> bool:
    """Interpret serialized booleans without treating ``"false"`` as true."""
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "verified", "valid"}
    return bool(value)


def evaluate_asset(
    asset: Mapping[str, Any],
    *,
    registry: Registry | None = None,
    require_registered: bool = True,
    allow_synthetic: bool = False,
    allow_cached: bool = False,
) -> AdmissionDecision:
    """Evaluate metadata for an asset before it is installed or enabled.

    ``registry`` is the existing local allow-list.  If the asset includes a
    signature field, it must be explicitly valid; if it has no signature
    evidence, registry plus an exact content hash is still required.  This
    keeps the gate useful on legacy assets while making unsigned admission an
    explicit, auditable exception instead of an accidental default.
    """
    kind = str(asset.get("kind", "")).strip()
    name = str(asset.get("name", "")).strip()
    path = str(asset.get("path", "")).strip()
    digest = str(asset.get("sha256", "")).strip().lower()
    provenance = str(asset.get("provenance", "")).strip().lower()
    carrier = str(asset.get("carrier", provenance)).strip().lower()
    state = str(asset.get("state", "")).strip().lower()
    assessment = str(asset.get("risk_assessment", "unassessed")).strip().lower()
    checks: list[AdmissionCheck] = []

    checks.append(_check("identity", bool(kind and name and path),
                         "kind, name and path are required" if not (kind and name and path)
                         else "asset identity is complete"))
    checks.append(_check("content_hash", len(digest) == 64 and all(
        character in "0123456789abcdef" for character in digest),
        "sha256 must be a 64-character hexadecimal digest" if len(digest) != 64
        or not all(character in "0123456789abcdef" for character in digest)
        else "content hash is present"))

    if carrier in BLOCKED_CARRIERS:
        carrier_ok = allow_cached and carrier in {"marketplace_cache", "codex_plugin_cache"}
        carrier_reason = "cache/dependency carrier is not an install source"
        if carrier_ok:
            carrier_reason = "cache carrier explicitly allowed for this check"
    elif carrier == "synthetic_test":
        carrier_ok = allow_synthetic
        carrier_reason = "synthetic asset requires explicit lab admission"
    else:
        carrier_ok = True
        carrier_reason = "carrier is eligible for admission"
    checks.append(_check("carrier", carrier_ok, carrier_reason))

    state_ok = allow_cached or state not in {"discovered", "cached"}
    checks.append(_check("state", state_ok,
                         "discovered/cached assets are inventory only" if not state_ok
                         else "asset state is eligible"))

    risk_ok = assessment not in BLOCKED_ASSESSMENTS
    checks.append(_check("risk_assessment", risk_ok,
                         "high-risk or confirmed-malicious assets are blocked" if not risk_ok
                         else "risk assessment is not an admission block"))

    signature_present = "signature_valid" in asset or "signed" in asset
    signature_ok = True
    if signature_present:
        signature_ok = _bool_value(asset.get("signature_valid", asset.get("signed", False)))
    checks.append(_check("signature", signature_ok,
                         "signature evidence is invalid or missing" if not signature_ok
                         else ("signature verified" if signature_present
                               else "no signature evidence; registry/hash policy applies")))

    registry_entry = registry.lookup(kind, name) if registry is not None else None
    registered_ok = not require_registered or registry_entry is not None
    hash_match = True
    if registry_entry is not None and registry_entry.get("sha256"):
        hash_match = str(registry_entry["sha256"]).lower() == digest
    checks.append(_check("registry", registered_ok,
                         "asset is not present in the trusted registry" if not registered_ok
                         else "asset is registered"))
    checks.append(_check("registry_hash", hash_match,
                         "content hash differs from the registered hash" if not hash_match
                         else "registered hash matches"))

    passed = all(check.passed for check in checks)
    failed = [check.name for check in checks if not check.passed]
    reason = "admission checks passed" if passed else "admission blocked: " + ", ".join(failed)
    return AdmissionDecision(
        allowed=passed,
        action="allow" if passed else "block",
        reason=reason,
        checks=tuple(checks),
        kind=kind,
        name=name,
        path=path,
        sha256=digest,
    )


def evaluate_path(
    path: str | Path,
    *,
    kind: str,
    name: str,
    registry: Registry | None = None,
    **options: Any,
) -> AdmissionDecision:
    """Hash a local asset and apply :func:`evaluate_asset`."""
    target = Path(path).expanduser()
    try:
        digest = sha256_path(target) if target.exists() else ""
    except OSError:
        digest = ""
    return evaluate_asset(
        {"kind": kind, "name": name, "path": str(target), "sha256": digest},
        registry=registry,
        **options,
    )
