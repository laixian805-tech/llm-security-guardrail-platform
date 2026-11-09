"""Deterministic asset identity and evidence-backed carrier classification."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from .models import (ActivationState, AssetCarrier, AssetKind, AssetRecord,
                     AssetState, InstallationState, RuntimeState)


def normalized_content_hash(path: str | Path) -> str:
    """Hash file/tree content with stable paths and normalized text newlines."""
    target = Path(path)
    digest = hashlib.sha256()
    if target.is_file():
        entries = [(target.name, target)]
    elif target.is_dir():
        entries = [(item.relative_to(target).as_posix(), item)
                   for item in sorted(target.rglob("*")) if item.is_file()]
    else:
        return ""
    for relative, item in entries:
        try:
            raw = item.read_bytes()
        except OSError:
            continue
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            content = raw
        else:
            content = text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")
        digest.update(content)
        digest.update(b"\0")
    return digest.hexdigest()


def canonical_path(path: str | Path) -> str:
    """Normalize a path for identity without requiring it to exist."""
    raw = str(path).replace("\\", "/")
    if not raw:
        return ""
    normalized = os.path.normpath(os.path.expanduser(raw)).replace("\\", "/")
    return normalized if normalized == "/" else normalized.rstrip("/")


def _parts(path: str | Path) -> tuple[str, ...]:
    return tuple(part.lower() for part in canonical_path(path).split("/") if part)


def infer_product(path: str | Path, product: str = "") -> str:
    if product.strip():
        return product.strip().lower()
    markers = {
        ".codex": "codex",
        ".claude": "claude-code",
        ".gemini": "gemini-cli",
        ".qwen": "qwen",
        ".openclaw": "openclaw",
        ".stepcode": "stepcode",
        ".codeium": "windsurf",
    }
    for marker, value in markers.items():
        if marker in _parts(path):
            return value
    return "unknown"


def classify_carrier(path: str | Path, *, synthetic: bool | None = None) -> AssetCarrier:
    parts = _parts(path)
    joined = "/" + "/".join(parts) + "/"
    if synthetic is True or "agentsec-assets" in parts or "fixtures/agentsec" in joined:
        return AssetCarrier.SYNTHETIC
    if any(parts[index:index + 3] == (".tmp", "plugins", "plugins")
           for index in range(max(0, len(parts) - 2))):
        return AssetCarrier.MARKETPLACE_CACHE
    if (".codex-system-skills.marker" in parts
            or any(parts[index:index + 3] == (".codex", "skills", ".system")
                   for index in range(max(0, len(parts) - 2)))):
        return AssetCarrier.PRODUCT_BUILTIN
    if any(part in {"node_modules", "site-packages", ".venv", "venv"}
           for part in parts):
        return AssetCarrier.VENDOR_DEPENDENCY
    for product_dir in (".claude", ".codex"):
        if product_dir in parts and "skills" in parts:
            path_parts = Path(canonical_path(path)).parts
            index = [part.lower() for part in path_parts].index(product_dir)
            prefix = Path(*path_parts[:index])
            try:
                is_user_root = prefix.resolve() == Path.home().resolve()
            except OSError:
                is_user_root = False
            return AssetCarrier.USER_INSTALLED if is_user_root else AssetCarrier.PROJECT_LOCAL
    if ".stepcode" in parts or ".openclaw" in parts:
        return AssetCarrier.USER_INSTALLED
    return AssetCarrier.UNKNOWN


def state_for_carrier(carrier: AssetCarrier, *, exists: bool = True) -> AssetState:
    if not exists:
        return AssetState.REMOVED
    if carrier == AssetCarrier.MARKETPLACE_CACHE:
        return AssetState.CACHED
    if carrier in {AssetCarrier.PRODUCT_BUILTIN, AssetCarrier.USER_INSTALLED,
                   AssetCarrier.PROJECT_LOCAL, AssetCarrier.SYNTHETIC}:
        return AssetState.INSTALLED
    return AssetState.DISCOVERED


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def derive_ids(*, product: str, kind: AssetKind | str, name: str,
               host: str, carrier: AssetCarrier | str, path: str,
               publisher: str = "unknown", namespace: str = "unknown",
               release_id: str = "") -> tuple[str, str]:
    kind_value = kind.value if isinstance(kind, AssetKind) else str(kind)
    carrier_value = carrier.value if isinstance(carrier, AssetCarrier) else str(carrier)
    logical = _digest("|".join((product.strip().lower() or "unknown",
                                kind_value.strip().lower(), name.strip().lower(),
                                publisher.strip().lower() or "unknown",
                                namespace.strip().lower() or "unknown")))
    instance = _digest("|".join((host.strip().lower(), carrier_value,
                                 canonical_path(path), release_id.strip())))
    return logical, instance


def derive_release_id(*, logical_id: str, version: str, content_hash: str,
                      source_uri: str = "") -> str:
    return _digest("|".join((logical_id, version.strip(), content_hash.strip().lower(),
                              source_uri.strip())))


def enrich_asset(asset: AssetRecord, *, host: str | None = None,
                 content_hash: str | None = None) -> AssetRecord:
    actual_host = host if host is not None else asset.host
    product = infer_product(asset.path, asset.product)
    carrier = (asset.carrier if asset.carrier != AssetCarrier.UNKNOWN
               else classify_carrier(asset.path))
    state = (asset.state if asset.state != AssetState.DISCOVERED
             else state_for_carrier(carrier, exists=bool(asset.path)))
    logical_id, _ = derive_ids(
        product=product, kind=asset.kind, name=asset.name, host=actual_host,
        carrier=carrier, path=asset.path, publisher=asset.publisher,
        namespace=asset.namespace,
    )
    logical_id = asset.logical_id or logical_id
    release_id = asset.release_id or derive_release_id(
        logical_id=logical_id, version=asset.version,
        content_hash=asset.content_hash or asset.sha256,
        source_uri=asset.source_uri,
    )
    _, instance_id = derive_ids(
        product=product, kind=asset.kind, name=asset.name, host=actual_host,
        carrier=carrier, path=asset.path, publisher=asset.publisher,
        namespace=asset.namespace, release_id=release_id,
    )
    digest = content_hash or asset.content_hash or asset.sha256
    return asset.model_copy(update={
        "host": actual_host,
        "product": product,
        "release_id": asset.release_id or release_id,
        "logical_id": logical_id,
        "instance_id": asset.instance_id or instance_id,
        "asset_id": asset.asset_id or instance_id,
        "content_hash": digest,
        "carrier": carrier,
        "state": state,
        "installation_state": (InstallationState.CACHED
                                if carrier == AssetCarrier.MARKETPLACE_CACHE
                                else InstallationState.INSTALLED
                                if carrier in {AssetCarrier.PRODUCT_BUILTIN,
                                                AssetCarrier.USER_INSTALLED,
                                                AssetCarrier.PROJECT_LOCAL,
                                                AssetCarrier.SYNTHETIC}
                                else asset.installation_state),
        "activation_state": asset.activation_state,
        "runtime_state": asset.runtime_state,
        "path": canonical_path(asset.path),
    })


def legacy_provenance(carrier: AssetCarrier) -> str:
    return {
        AssetCarrier.MARKETPLACE_CACHE: "codex_plugin_cache",
        AssetCarrier.PRODUCT_BUILTIN: "codex_builtin",
        AssetCarrier.SYNTHETIC: "synthetic_test",
        AssetCarrier.VENDOR_DEPENDENCY: "dependency_or_vendor_content",
        AssetCarrier.USER_INSTALLED: "user_installed_cli_content",
        AssetCarrier.PROJECT_LOCAL: "project_local_content",
    }.get(carrier, "unknown")
