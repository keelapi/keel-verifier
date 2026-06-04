"""Canonical permit-binding payload builders.

Ported from keel-api ``app/services/permit_binding.py`` at commit
03bcd1d964c6f25f9c985850d1452a19ee771a5a. Keep these builders byte-stable:
the verifier must not import keel-api, but it must produce identical canonical
bytes for legitimate permits.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from typing import Any


SUPPORTED_BINDING_VERSIONS = frozenset({"v1", "v2", "v3", "v4"})


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _sha256_hex(value: bytes | str) -> str:
    data = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(data).hexdigest()


def _normalize_datetime(value: Any) -> str | None:
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return None
        parse_value = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
        try:
            value = datetime.fromisoformat(parse_value)
        except ValueError:
            return None
    if not isinstance(value, datetime):
        return None
    aware = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    return aware.astimezone(timezone.utc).isoformat()


def _normalize_uuid(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, uuid.UUID):
        return str(value)
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, AttributeError, TypeError):
        return None


def _normalize_target_list(targets: Iterable[Any] | None) -> list[dict[str, str]]:
    if not targets:
        return []
    out: list[dict[str, str]] = []
    for target in targets:
        provider = getattr(target, "provider", None) or (
            target.get("provider") if isinstance(target, Mapping) else None
        )
        model = getattr(target, "model", None) or (
            target.get("model") if isinstance(target, Mapping) else None
        )
        if provider is None or model is None:
            continue
        out.append(
            {"provider": str(provider).strip().lower(), "model": str(model).strip()}
        )
    return out


def canonical_binding_payload_v1(
    *,
    permit_id: uuid.UUID | str,
    project_id: uuid.UUID | str,
    parent_permit_id: uuid.UUID | str | None,
    decision: str,
    reason: str,
    provider: str,
    model: str,
    operation: str | None,
    action_name: str,
    request_fingerprint: str | None,
    constraints: Mapping[str, Any] | None,
    routing: Mapping[str, Any] | None,
    policy_id: str,
    policy_version: str,
    policy_snapshot_hash: str | None,
    issued_at: datetime | str,
    expires_at: datetime | str | None,
    is_dry_run: bool = False,
    binding_key_id: str | None = None,
    final_request_hash: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "binding_version": "v1",
        "permit_id": _normalize_uuid(permit_id),
        "project_id": _normalize_uuid(project_id),
        "parent_permit_id": _normalize_uuid(parent_permit_id),
        "decision": (decision or "").strip().lower(),
        "reason": (reason or "").strip(),
        "provider": (provider or "").strip().lower(),
        "model": (model or "").strip(),
        "operation": (operation or "").strip().lower() or None,
        "action_name": (action_name or "").strip(),
        "request_fingerprint": (request_fingerprint or "").strip().lower() or None,
        "constraints": _to_canonical(constraints),
        "routing": _canonical_routing(routing),
        "policy_id": (policy_id or "").strip(),
        "policy_version": (policy_version or "").strip(),
        "policy_snapshot_hash": (policy_snapshot_hash or "").strip().lower() or None,
        "issued_at": _normalize_datetime(issued_at),
        "expires_at": _normalize_datetime(expires_at),
        "is_dry_run": bool(is_dry_run),
        "binding_key_id": (binding_key_id or "").strip() or None,
        "final_request_hash": (final_request_hash or "").strip().lower() or None,
    }
    return payload


def canonical_binding_payload_v2(
    *,
    permit_id: uuid.UUID | str,
    project_id: uuid.UUID | str,
    parent_permit_id: uuid.UUID | str | None,
    decision: str,
    reason: str,
    provider: str,
    model: str,
    operation: str | None,
    action_name: str,
    request_fingerprint: str | None,
    constraints: Mapping[str, Any] | None,
    routing: Mapping[str, Any] | None,
    policy_id: str,
    policy_version: str,
    policy_snapshot_hash: str | None,
    issued_at: datetime | str,
    expires_at: datetime | str | None,
    is_dry_run: bool = False,
    binding_key_id: str | None = None,
    final_request_hash: str | None = None,
    binding_session_id: str | None = None,
    binding_session_event_hash: str | None = None,
    binding_project_anchor_hash: str | None = None,
    permit_chain_role: str | None = "session_root",
    inherits_from: uuid.UUID | str | None = None,
    authority_delta: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "binding_version": "v2",
        "permit_id": _normalize_uuid(permit_id),
        "project_id": _normalize_uuid(project_id),
        "parent_permit_id": _normalize_uuid(parent_permit_id),
        "decision": (decision or "").strip().lower(),
        "reason": (reason or "").strip(),
        "provider": (provider or "").strip().lower(),
        "model": (model or "").strip(),
        "operation": (operation or "").strip().lower() or None,
        "action_name": (action_name or "").strip(),
        "request_fingerprint": (request_fingerprint or "").strip().lower() or None,
        "constraints": _to_canonical(constraints),
        "routing": _canonical_routing(routing),
        "policy_id": (policy_id or "").strip(),
        "policy_version": (policy_version or "").strip(),
        "policy_snapshot_hash": (policy_snapshot_hash or "").strip().lower() or None,
        "issued_at": _normalize_datetime(issued_at),
        "expires_at": _normalize_datetime(expires_at),
        "is_dry_run": bool(is_dry_run),
        "binding_key_id": (binding_key_id or "").strip() or None,
        "final_request_hash": (final_request_hash or "").strip().lower() or None,
        "binding_session_id": (binding_session_id or "").strip() or None,
        "binding_session_event_hash": (
            binding_session_event_hash or ""
        ).strip().lower()
        or None,
        "binding_project_anchor_hash": (
            binding_project_anchor_hash or ""
        ).strip().lower()
        or None,
        "permit_chain_role": _normalize_permit_chain_role(permit_chain_role),
        "inherits_from": _normalize_uuid(inherits_from),
        "authority_delta": _to_canonical(authority_delta),
    }
    return payload


def canonical_binding_payload_v3(
    *,
    permit_id: uuid.UUID | str,
    project_id: uuid.UUID | str,
    parent_permit_id: uuid.UUID | str | None,
    decision: str,
    reason: str,
    provider: str,
    model: str,
    operation: str | None,
    action_name: str,
    request_fingerprint: str | None,
    constraints: Mapping[str, Any] | None,
    routing: Mapping[str, Any] | None,
    policy_id: str,
    policy_version: str,
    policy_snapshot_hash: str | None,
    issued_at: datetime | str,
    expires_at: datetime | str | None,
    is_dry_run: bool = False,
    binding_key_id: str | None = None,
    final_request_hash: str | None = None,
    binding_session_id: str | None = None,
    binding_session_event_hash: str | None = None,
    binding_project_anchor_hash: str | None = None,
    permit_chain_role: str | None = "session_root",
    inherits_from: uuid.UUID | str | None = None,
    authority_delta: Mapping[str, Any] | None = None,
    spend_scope_hash: str | None = None,
) -> dict[str, Any]:
    payload = canonical_binding_payload_v2(
        permit_id=permit_id,
        project_id=project_id,
        parent_permit_id=parent_permit_id,
        decision=decision,
        reason=reason,
        provider=provider,
        model=model,
        operation=operation,
        action_name=action_name,
        request_fingerprint=request_fingerprint,
        constraints=constraints,
        routing=routing,
        policy_id=policy_id,
        policy_version=policy_version,
        policy_snapshot_hash=policy_snapshot_hash,
        issued_at=issued_at,
        expires_at=expires_at,
        is_dry_run=is_dry_run,
        binding_key_id=binding_key_id,
        final_request_hash=final_request_hash,
        binding_session_id=binding_session_id,
        binding_session_event_hash=binding_session_event_hash,
        binding_project_anchor_hash=binding_project_anchor_hash,
        permit_chain_role=permit_chain_role,
        inherits_from=inherits_from,
        authority_delta=authority_delta,
    )
    payload["binding_version"] = "v3"
    payload["spend_scope_hash"] = (spend_scope_hash or "").strip().lower() or None
    return payload


def canonical_binding_payload_v4(
    *,
    delegation_policy_hash: str | None = None,
    **v3_fields: Any,
) -> dict[str, Any]:
    payload = canonical_binding_payload_v3(
        **_filter_fields_for_version(v3_fields, "v3")
    )
    payload["binding_version"] = "v4"
    payload["delegation_policy_hash"] = (
        (delegation_policy_hash or "").strip().lower() or None
    )
    return payload


CANONICAL_PAYLOAD_BUILDERS = {
    "v1": canonical_binding_payload_v1,
    "v2": canonical_binding_payload_v2,
    "v3": canonical_binding_payload_v3,
    "v4": canonical_binding_payload_v4,
}


def _filter_fields_for_version(
    fields: Mapping[str, Any],
    binding_version: str,
) -> dict[str, Any]:
    builder = CANONICAL_PAYLOAD_BUILDERS.get(binding_version)
    if builder is None:
        raise ValueError(f"Unsupported binding_version: {binding_version}")
    signature = inspect.signature(builder)
    if any(
        parameter.kind == inspect.Parameter.VAR_KEYWORD
        for parameter in signature.parameters.values()
    ):
        return dict(fields)
    accepted = set(signature.parameters)
    return {key: value for key, value in fields.items() if key in accepted}


def canonical_binding_payload(
    *,
    binding_version: str,
    **fields: Any,
) -> dict[str, Any]:
    normalized_version = (binding_version or "").strip()
    builder = CANONICAL_PAYLOAD_BUILDERS.get(normalized_version)
    if builder is None:
        raise ValueError(f"Unsupported binding_version: {binding_version}")
    return builder(**_filter_fields_for_version(fields, normalized_version))


def _canonical_routing(routing: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(routing, Mapping):
        return None
    requested_provider = routing.get("requested_provider")
    requested_model = routing.get("requested_model")
    selected_provider = routing.get("selected_provider")
    selected_model = routing.get("selected_model")
    fallback_chain = routing.get("fallback_chain") or []
    fallback_occurred = routing.get("fallback_occurred")
    canonical: dict[str, Any] = {
        "requested_provider": (
            str(requested_provider).strip().lower() if requested_provider else None
        ),
        "requested_model": str(requested_model).strip() if requested_model else None,
        "selected_provider": (
            str(selected_provider).strip().lower() if selected_provider else None
        ),
        "selected_model": str(selected_model).strip() if selected_model else None,
        "fallback_chain": _normalize_target_list(fallback_chain),
        "reason_code": (
            str(routing.get("reason_code")).strip()
            if routing.get("reason_code")
            else None
        ),
        "fallback_occurred": (
            bool(fallback_occurred) if fallback_occurred is not None else None
        ),
        "reason_metadata": _to_canonical(routing.get("reason_metadata")),
    }
    return canonical


def _to_canonical(value: Any) -> Any:
    if value is None:
        return None
    if is_dataclass(value) and not isinstance(value, type):
        return _to_canonical(asdict(value))
    if isinstance(value, Mapping):
        return {str(k): _to_canonical(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        if isinstance(value, (set, frozenset)):
            return sorted(_to_canonical(v) for v in value)
        return [_to_canonical(v) for v in value]
    if isinstance(value, datetime):
        return _normalize_datetime(value)
    if isinstance(value, uuid.UUID):
        return str(value)
    return value


def canonical_spend_scope_payload(spend_scope: Mapping[str, Any] | None) -> str | None:
    """Return the canonical SHA-256 digest for a spend_scope block."""

    if spend_scope is None:
        return None
    if not isinstance(spend_scope, Mapping):
        return None

    try:
        canonical = {
            "amount_max": int(spend_scope["amount_max"]),
            "currency_class": str(spend_scope["currency_class"]).strip().upper(),
            "cadence": str(spend_scope["cadence"]).strip().lower(),
            "ttl_seconds": int(spend_scope["ttl_seconds"]),
            "purpose_binding": str(spend_scope.get("purpose_binding", "other"))
            .strip()
            .lower(),
            "recipient_address_digest": (
                (spend_scope.get("recipient_address_digest") or "").strip().lower()
                or None
            ),
            "merchant_id_digest": (
                (spend_scope.get("merchant_id_digest") or "").strip().lower() or None
            ),
            "description_digest": (
                (spend_scope.get("description_digest") or "").strip().lower() or None
            ),
        }
    except (KeyError, TypeError, ValueError):
        return None
    return _sha256_hex(_canonical_json(canonical))


def canonical_delegation_policy_payload(
    delegation_policy: Mapping[str, Any] | None,
) -> str | None:
    """Return the canonical SHA-256 digest for a delegation_policy block."""

    if not isinstance(delegation_policy, Mapping):
        return None
    raw_delegations = delegation_policy.get("delegations")
    if not isinstance(raw_delegations, list):
        return None

    try:
        entries: list[dict[str, Any]] = []
        for raw_delegation in raw_delegations:
            if not isinstance(raw_delegation, Mapping):
                return None
            allowed_purpose_bindings = raw_delegation.get(
                "allowed_purpose_bindings"
            )
            entries.append(
                {
                    "verb": str(raw_delegation["verb"]).strip().lower(),
                    "amount_max": (
                        int(raw_delegation["amount_max"])
                        if raw_delegation.get("amount_max") is not None
                        else None
                    ),
                    "currency_class": (
                        str(raw_delegation["currency_class"]).strip().upper()
                        if raw_delegation.get("currency_class") is not None
                        else None
                    ),
                    "ttl_seconds": (
                        int(raw_delegation["ttl_seconds"])
                        if raw_delegation.get("ttl_seconds") is not None
                        else None
                    ),
                    "allowed_purpose_bindings": (
                        sorted(
                            {
                                str(purpose_binding).strip().lower()
                                for purpose_binding in allowed_purpose_bindings
                            }
                        )
                        if allowed_purpose_bindings is not None
                        else None
                    ),
                }
            )
        canonical = {"delegations": sorted(entries, key=lambda item: item["verb"])}
    except (KeyError, TypeError, ValueError):
        return None
    return _sha256_hex(_canonical_json(canonical))


def compute_canonical_binding_hash(payload: Mapping[str, Any]) -> str:
    return _sha256_hex(_canonical_json(payload))


def _normalize_permit_chain_role(value: str | None) -> str:
    normalized = str(value or "").strip().lower()
    return normalized or "session_root"


__all__ = [
    "SUPPORTED_BINDING_VERSIONS",
    "_canonical_json",
    "canonical_binding_payload",
    "canonical_binding_payload_v1",
    "canonical_binding_payload_v2",
    "canonical_binding_payload_v3",
    "canonical_binding_payload_v4",
    "canonical_delegation_policy_payload",
    "canonical_spend_scope_payload",
    "compute_canonical_binding_hash",
]
