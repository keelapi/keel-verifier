"""Fact-profile-driven adjudication for ``keel.permit_exact/v2`` bodies.

The signed Permit decision is the authority source. Embedded contracts are
replay inputs, receipt fields are comparison projections, and every declared
universal claim receives a structured result even when its evidence is absent.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
import hashlib
from importlib import resources
import json
from typing import Any, Callable, Mapping

import jsonschema
from referencing import Registry, Resource
import rfc8785

from keel_verifier.action_classification_derivation import (
    default_trust_config,
    derive,
)
from keel_verifier.canonical.permit_binding import (
    canonical_resource_attributes_payload,
)


PROFILE = "keel.permit_exact/v2"
PROFILE_VERSION = 2
_DATA_ROOT = "data/permit_to_x"
_CLAIM_REGISTRY_ID = "keel.verifier_claim_registry.v2"
_UNIVERSAL_SEMANTICS_ID = "keel.permit.universal_verification.v1"
_PROVIDER_RECEIPT_SEMANTICS_ID = "keel.provider.receipt_state.v1"
_SAFE_LOW_ENTROPY_METHODS = {
    "keel.salted_sha256_jcs.v1",
    "keel.randomized_sha256_jcs.v1",
    "keel.hmac_sha256_jcs.v1",
    "keel.opaque_reference.v1",
    "signed_cleartext",
}
_EXTERNAL_CLAIMS = {
    "permit.decision.v1",
    "permit.review_transition.v1",
}
UNIVERSAL_CLAIMS = (
    "permit.type.v1",
    "permit.exact_target.v1",
    "permit.material_request.v1",
    "permit.valid_at_dispatch.v1",
    "permit.revocation_at_dispatch.v1",
    "permit.enforced_at_certified_boundary.v1",
    "permit.bounded_use.v1",
    "permit.single_use.v1",
    "permit.replay_prevented.v1",
    "permit.idempotency_bound.v1",
    "provider.receipt_state.v1",
    "provider.rejected.v1",
    "provider.accepted.v1",
    "provider.completed.v1",
)
SignedArtifactVerifier = Callable[
    [Mapping[str, Any], str, str],
    tuple[bool, str | None],
]


@dataclass(frozen=True)
class ExactClaimAssessment:
    name: str
    verdict: str
    reason_code: str
    message: str
    evidence: tuple[str, ...] = ()
    does_not_establish: tuple[str, ...] = ()


@dataclass(frozen=True)
class PermitExactV2Result:
    permit_id: str
    project_id: str
    semantic_id: str | None
    fact_profile_id: str | None
    authorized_action: str | None
    claims: tuple[ExactClaimAssessment, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class _ResolvedContracts:
    selector_registry: dict[str, Any]
    selector_entry: dict[str, Any]
    fact_registry: dict[str, Any]
    fact_profile: dict[str, Any]
    facts_schema: dict[str, Any]
    universal_semantics: dict[str, Any]
    provider_receipt_semantics: dict[str, Any] | None


class _AdjudicationError(ValueError):
    def __init__(self, verdict: str, reason_code: str, message: str):
        super().__init__(message)
        self.verdict = verdict
        self.reason_code = reason_code


def _resource(path: str):
    if path.startswith("../"):
        return resources.files("keel_verifier").joinpath(f"data/{path[3:]}")
    return resources.files("keel_verifier").joinpath(f"{_DATA_ROOT}/{path}")


def _bytes(path: str) -> bytes:
    return _resource(path).read_bytes()


def _json(path: str) -> dict[str, Any]:
    value = json.loads(_resource(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"vendored artifact {path} must be an object")
    return value


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _jcs_digest(value: Mapping[str, Any]) -> str:
    return _sha256(rfc8785.dumps(dict(value)))


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _pointer(value: Mapping[str, Any], path: str) -> Any:
    if not isinstance(path, str) or not path.startswith("/"):
        raise KeyError(path)
    current: Any = value
    for raw_part in path.split("/")[1:]:
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, Mapping) or part not in current:
            raise KeyError(path)
        current = current[part]
    return current


def _one_entry(values: Any, *, key: str, expected: str) -> dict[str, Any]:
    if not isinstance(values, list):
        raise _AdjudicationError(
            "unverifiable_scope",
            "PERMIT_TYPE_UNRESOLVED",
            f"registry {key} entries are missing",
        )
    matches = [
        dict(value)
        for value in values
        if isinstance(value, dict) and value.get(key) == expected
    ]
    if len(matches) != 1:
        raise _AdjudicationError(
            "insufficient_evidence",
            "PERMIT_TYPE_UNRESOLVED",
            f"registry must contain exactly one {key}={expected}",
        )
    return matches[0]


@lru_cache(maxsize=1)
def _claim_evidence_ceilings() -> dict[str, tuple[str, ...]]:
    registry = _json("../claim_registry/v2.json")
    ceilings: dict[str, tuple[str, ...]] = {}
    for claim in registry.get("claims", []):
        if not isinstance(claim, Mapping):
            continue
        name = claim.get("name")
        values = claim.get("does_not_establish")
        if not isinstance(name, str) or not isinstance(values, list):
            continue
        ceilings[name] = tuple(str(value) for value in values if isinstance(value, str))
    return ceilings


def _assessment(
    name: str,
    verdict: str,
    reason_code: str,
    message: str,
    *,
    evidence: tuple[str, ...] = (),
    does_not_establish: tuple[str, ...] = (),
) -> ExactClaimAssessment:
    evidence_ceiling = tuple(
        dict.fromkeys(
            (
                *_claim_evidence_ceilings().get(name, ()),
                *does_not_establish,
            )
        )
    )
    return ExactClaimAssessment(
        name=name,
        verdict=verdict,
        reason_code=reason_code,
        message=message,
        evidence=evidence,
        does_not_establish=evidence_ceiling,
    )


def _schema_registry() -> tuple[dict[str, Any], Registry]:
    names = (
        "schemas/permit-exact-pack-v2.schema.json",
        "schemas/permit-semantic-binding-v2.schema.json",
        "schemas/adapter-certification-v1.schema.json",
        "schemas/deployment-assurance-v1.schema.json",
        "schemas/runtime-enforcement-proof-v1.schema.json",
        "schemas/permit-bounded-use-v1.schema.json",
        "schemas/permit-selective-disclosure-v1.schema.json",
        "schemas/provider-receipt-v1.schema.json",
    )
    schemas = [_json(name) for name in names]
    registry = Registry()
    for schema in schemas:
        schema_id = schema.get("$id")
        if not isinstance(schema_id, str):
            raise RuntimeError("vendored Permit-to-X schema is missing $id")
        registry = registry.with_resource(
            schema_id,
            Resource.from_contents(schema),
        )
    return schemas[0], registry


def _validate_schema(instance: Any, schema_name: str) -> None:
    schema = _json(f"schemas/{schema_name}")
    jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    ).validate(instance)


def _validate_exact_pack_schema(body: Mapping[str, Any]) -> None:
    schema, registry = _schema_registry()
    validation_body = dict(body)
    # Dynamic child evidence is adjudicated claim-by-claim below so one invalid
    # child cannot collapse every declared claim into a generic pack error.
    # Preserve malformed outer container types here; only defer structurally
    # valid collections to their dedicated signed-artifact validators.
    if isinstance(body.get("provider_receipts"), list):
        validation_body["provider_receipts"] = []
    if isinstance(body.get("bounded_use_transitions"), list):
        validation_body["bounded_use_transitions"] = []
    if isinstance(body.get("enforcement_evidence"), Mapping):
        validation_body["enforcement_evidence"] = None
    jsonschema.Draft202012Validator(
        schema,
        registry=registry,
        format_checker=jsonschema.FormatChecker(),
    ).validate(validation_body)


def _decode_pin(
    pin: Any,
    *,
    label: str,
    bundled_path: str,
    artifact_id: str | None,
) -> tuple[dict[str, Any], str]:
    if not isinstance(pin, Mapping):
        raise _AdjudicationError(
            "insufficient_evidence",
            "PERMIT_CONTRACT_PIN_MISSING",
            f"{label} contract pin is missing",
        )
    if artifact_id is not None and pin.get("artifact_id") != artifact_id:
        raise _AdjudicationError(
            "disproved",
            "PERMIT_CONTRACT_PIN_ID_MISMATCH",
            f"{label} artifact identity does not match the released contract",
        )
    content = pin.get("content_base64")
    if not isinstance(content, str):
        raise _AdjudicationError(
            "insufficient_evidence",
            "PERMIT_CONTRACT_PIN_MISSING",
            f"{label} contract bytes are missing",
        )
    try:
        raw = base64.b64decode(content, validate=True)
    except Exception as exc:
        raise _AdjudicationError(
            "disproved",
            "PERMIT_CONTRACT_PIN_INVALID",
            f"{label} contract bytes are invalid base64: {exc}",
        ) from exc
    actual_digest = _sha256(raw)
    if pin.get("sha256") != actual_digest:
        raise _AdjudicationError(
            "disproved",
            "PERMIT_CONTRACT_PIN_DIGEST_MISMATCH",
            f"{label} contract digest does not match embedded bytes",
        )
    released = _bytes(bundled_path)
    if raw != released:
        raise _AdjudicationError(
            "unverifiable_scope",
            "PERMIT_CONTRACT_PIN_UNSUPPORTED",
            f"{label} contract is not allowlisted by this verifier release",
        )
    try:
        payload = json.loads(raw)
    except Exception as exc:
        raise _AdjudicationError(
            "disproved",
            "PERMIT_CONTRACT_PIN_INVALID",
            f"{label} contract is not valid JSON: {exc}",
        ) from exc
    if not isinstance(payload, dict):
        raise _AdjudicationError(
            "disproved",
            "PERMIT_CONTRACT_PIN_INVALID",
            f"{label} contract must be an object",
        )
    payload_version = payload.get("version")
    if payload_version is not None and pin.get("version") != str(payload_version):
        raise _AdjudicationError(
            "disproved",
            "PERMIT_CONTRACT_PIN_VERSION_MISMATCH",
            f"{label} contract version does not match embedded bytes",
        )
    return payload, actual_digest


def _selector_matches(
    entry: Mapping[str, Any],
    binding: Mapping[str, Any],
) -> bool:
    if binding.get("trusted_source_kind") not in entry.get(
        "trusted_source_kinds", []
    ):
        return False
    match = entry.get("match")
    if not isinstance(match, Mapping):
        return False
    comparisons = (
        ("action_names", "action_name"),
        ("operations", "operation"),
        ("allowed_chain_roles", "chain_role"),
    )
    for registry_field, binding_field in comparisons:
        values = match.get(registry_field)
        if isinstance(values, list) and binding.get(binding_field) not in values:
            return False
    surfaces = match.get("required_surfaces")
    return not (
        isinstance(surfaces, list)
        and binding.get("governed_surface") not in surfaces
    )


def _resolve_contracts(
    body: Mapping[str, Any],
    *,
    binding: Mapping[str, Any],
    facts: Mapping[str, Any],
) -> _ResolvedContracts:
    pins = body.get("contract_pins")
    if not isinstance(pins, Mapping):
        raise _AdjudicationError(
            "insufficient_evidence",
            "PERMIT_CONTRACT_PIN_MISSING",
            "contract_pins are missing",
        )
    claim_registry, claim_digest = _decode_pin(
        pins.get("claim_registry"),
        label="claim registry",
        bundled_path="../claim_registry/v2.json",
        artifact_id=_CLAIM_REGISTRY_ID,
    )
    selector_registry, selector_digest = _decode_pin(
        pins.get("semantic_selector_registry"),
        label="semantic selector registry",
        bundled_path="semantic_registry/v3.json",
        artifact_id="keel.permit.semantic_selector_registry",
    )
    fact_registry, fact_digest = _decode_pin(
        pins.get("fact_profile_registry"),
        label="fact profile registry",
        bundled_path="fact_profiles/v2.json",
        artifact_id="keel.permit.fact_profile_registry",
    )
    universal_semantics, universal_digest = _decode_pin(
        pins.get("universal_semantics"),
        label="universal semantics",
        bundled_path="../semantics/permit/universal_verification_v1.json",
        artifact_id=_UNIVERSAL_SEMANTICS_ID,
    )
    if claim_registry.get("version") != "verifier-claims.v2":
        raise _AdjudicationError(
            "unverifiable_scope",
            "PERMIT_CONTRACT_PIN_UNSUPPORTED",
            "claim registry is not verifier-claims.v2",
        )
    semantic_id = str(binding.get("semantic_id") or "")
    selector_entry = _one_entry(
        selector_registry.get("entries"),
        key="semantic_id",
        expected=semantic_id,
    )
    matched_entries = [
        entry
        for entry in selector_registry.get("entries", [])
        if isinstance(entry, Mapping) and _selector_matches(entry, binding)
    ]
    if len(matched_entries) != 1 or matched_entries[0].get(
        "semantic_id"
    ) != semantic_id:
        raise _AdjudicationError(
            "insufficient_evidence",
            "PERMIT_TYPE_UNRESOLVED",
            "trusted binding does not resolve exactly one matching semantic",
        )
    fact_profile_id = str(binding.get("fact_profile_id") or "")
    fact_profile = _one_entry(
        fact_registry.get("profiles"),
        key="fact_profile_id",
        expected=fact_profile_id,
    )
    if semantic_id not in fact_profile.get("semantic_ids", []):
        raise _AdjudicationError(
            "disproved",
            "PERMIT_TYPE_FACT_PROFILE_MISMATCH",
            "fact profile is not admitted for the signed semantic",
        )
    schema_path = str(fact_profile.get("facts_schema") or "")
    if not schema_path.startswith("schemas/"):
        raise _AdjudicationError(
            "unverifiable_scope",
            "PERMIT_FACT_SCHEMA_UNSUPPORTED",
            "fact profile facts_schema is not a supported relative path",
        )
    facts_schema, facts_schema_digest = _decode_pin(
        pins.get("authorization_facts_schema"),
        label="authorization facts schema",
        bundled_path=schema_path,
        artifact_id=None,
    )
    provider_semantics = None
    provider_pin = pins.get("provider_receipt_semantics")
    if provider_pin is not None:
        provider_semantics, _ = _decode_pin(
            provider_pin,
            label="provider receipt semantics",
            bundled_path="../semantics/permit/provider_receipt_state_v1.json",
            artifact_id=_PROVIDER_RECEIPT_SEMANTICS_ID,
        )

    expected_pairs = (
        (binding.get("claim_registry_version"), claim_registry.get("version")),
        (binding.get("claim_registry_digest"), claim_digest),
        (
            binding.get("selector_registry_version"),
            selector_registry.get("version"),
        ),
        (binding.get("selector_registry_digest"), selector_digest),
        (
            binding.get("fact_profile_registry_version"),
            fact_registry.get("version"),
        ),
        (binding.get("fact_profile_registry_digest"), fact_digest),
        (
            binding.get("universal_semantics_id"),
            universal_semantics.get("id"),
        ),
        (binding.get("universal_semantics_digest"), universal_digest),
        (binding.get("selector_entry_digest"), _jcs_digest(selector_entry)),
        (binding.get("fact_profile_entry_digest"), _jcs_digest(fact_profile)),
        (
            binding.get("authorization_facts_schema_digest"),
            facts_schema_digest,
        ),
        (binding.get("authorization_facts_digest"), _jcs_digest(facts)),
        (binding.get("authorization_facts_canonicalization"), "rfc8785"),
        (
            pins.get("semantic_selector_entry_digest"),
            _jcs_digest(selector_entry),
        ),
        (
            pins.get("fact_profile_entry_digest"),
            _jcs_digest(fact_profile),
        ),
    )
    if any(actual != expected for actual, expected in expected_pairs):
        raise _AdjudicationError(
            "disproved",
            "PERMIT_CONTRACT_BINDING_MISMATCH",
            "signed semantic or fact binding does not match embedded contracts",
        )
    return _ResolvedContracts(
        selector_registry=selector_registry,
        selector_entry=selector_entry,
        fact_registry=fact_registry,
        fact_profile=fact_profile,
        facts_schema=facts_schema,
        universal_semantics=universal_semantics,
        provider_receipt_semantics=provider_semantics,
    )


def _verify_privacy_profile(
    *,
    fact_registry: Mapping[str, Any],
    fact_profile: Mapping[str, Any],
    facts: Mapping[str, Any],
) -> None:
    disclosure = fact_registry.get("disclosure_contract")
    if not isinstance(disclosure, Mapping):
        raise _AdjudicationError(
            "unverifiable_scope",
            "DISCLOSURE_CONTRACT_MISSING",
            "fact registry disclosure contract is missing",
        )
    fields = fact_profile.get("fields")
    if not isinstance(fields, list):
        raise _AdjudicationError(
            "unverifiable_scope",
            "DISCLOSURE_CONTRACT_MISSING",
            "fact profile disclosure fields are missing",
        )
    for field_contract in fields:
        if not isinstance(field_contract, Mapping):
            continue
        path = str(field_contract.get("path") or "")
        if field_contract.get("required_for_authorization"):
            try:
                _pointer(facts, path)
            except KeyError as exc:
                raise _AdjudicationError(
                    "disproved",
                    "PERMIT_AUTHORIZATION_FACT_MISSING",
                    f"required authorization fact {path} is missing",
                ) from exc
        method = field_contract.get("commitment_method")
        if (
            field_contract.get("low_entropy_possible")
            and method not in _SAFE_LOW_ENTROPY_METHODS
        ):
            raise _AdjudicationError(
                "disproved",
                "DISCLOSURE_LOW_ENTROPY_PLAIN_HASH_FORBIDDEN",
                f"low-entropy fact {path} uses unsafe commitment method {method!r}",
            )
        if method in _SAFE_LOW_ENTROPY_METHODS - {
            "signed_cleartext",
            "keel.opaque_reference.v1",
        }:
            try:
                fact_value = _pointer(facts, path)
            except KeyError:
                continue
            if not isinstance(fact_value, Mapping) or fact_value.get(
                "method"
            ) != method:
                raise _AdjudicationError(
                    "disproved",
                    "DISCLOSURE_COMMITMENT_METHOD_MISMATCH",
                    f"fact {path} does not use its declared commitment method",
                )


def _verify_profile_classification(
    *,
    fact_profile: Mapping[str, Any],
    signed_attributes: Mapping[str, Any],
) -> None:
    classification_path = fact_profile.get("classification_evidence_path")
    if not isinstance(classification_path, str):
        return
    classification = _pointer(signed_attributes, classification_path)
    if fact_profile.get(
        "classification_semantics_id"
    ) != "keel.permit.action_classification_derivation.v1":
        raise _AdjudicationError(
            "unverifiable_scope",
            "PERMIT_CLASSIFICATION_COMPARATOR_UNSUPPORTED",
            "fact profile classification comparator is not implemented",
        )
    if not isinstance(classification, Mapping):
        raise _AdjudicationError(
            "disproved",
            "PERMIT_CLASSIFICATION_INVALID",
            "signed action classification is not an object",
        )
    derived = derive(dict(classification), default_trust_config())
    if (
        derived.outcome != "valid"
        or derived.authorized_action != fact_profile.get("authorized_action")
    ):
        raise _AdjudicationError(
            "disproved",
            "PERMIT_CLASSIFICATION_MISMATCH",
            "signed action classification does not re-derive the profile action",
        )


def _signed_artifact_status(
    artifact: Mapping[str, Any],
    *,
    schema_name: str,
    purpose: str,
    signed_at_field: str,
    verifier: SignedArtifactVerifier | None,
) -> tuple[bool, str | None]:
    try:
        _validate_schema(artifact, schema_name)
    except jsonschema.ValidationError as exc:
        return False, f"schema invalid: {exc.message}"
    unsigned = {
        key: value
        for key, value in artifact.items()
        if key not in {"canonical_hash", "signature"}
    }
    expected_hash = _jcs_digest(unsigned)
    if artifact.get("canonical_hash") != expected_hash:
        return False, "canonical_hash does not match RFC 8785 signed fields"
    if verifier is None:
        return False, "trusted signature verifier is unavailable"
    return verifier(artifact, purpose, signed_at_field)


def _signed_maximum_uses(canonical_payload: Mapping[str, Any]) -> int | None:
    candidates: list[Any] = []
    constraints = canonical_payload.get("constraints")
    if isinstance(constraints, Mapping):
        usage = constraints.get("usage_limits")
        if isinstance(usage, Mapping):
            candidates.extend(
                [usage.get("maximum_uses"), usage.get("max_calls")]
            )
        candidates.extend(
            [constraints.get("maximum_uses"), constraints.get("max_calls")]
        )
    usage = canonical_payload.get("usage_limits")
    if isinstance(usage, Mapping):
        candidates.extend([usage.get("maximum_uses"), usage.get("max_calls")])
    return next(
        (
            int(value)
            for value in candidates
            if isinstance(value, int) and not isinstance(value, bool) and value >= 1
        ),
        None,
    )


def _provider_receipt_claims(
    *,
    body: Mapping[str, Any],
    facts: Mapping[str, Any],
    binding: Mapping[str, Any],
    fact_profile: Mapping[str, Any],
    semantics: Mapping[str, Any] | None,
) -> dict[str, ExactClaimAssessment]:
    claims: dict[str, ExactClaimAssessment] = {}
    receipts = body.get("provider_receipts")
    if not isinstance(receipts, list) or not receipts:
        missing = _assessment(
            "provider.receipt_state.v1",
            "insufficient_evidence",
            "PROVIDER_STATE_EVIDENCE_MISSING",
            "no provider receipt evidence was supplied",
            evidence=("body.provider_receipts",),
        )
        claims[missing.name] = missing
        for name in (
            "provider.rejected.v1",
            "provider.accepted.v1",
            "provider.completed.v1",
        ):
            claims[name] = _assessment(
                name,
                "insufficient_evidence",
                "PROVIDER_STATE_EVIDENCE_MISSING",
                "the declared provider-state claim has no provider receipt evidence",
                evidence=("body.provider_receipts",),
            )
        return claims
    if semantics is None:
        invalid = _assessment(
            "provider.receipt_state.v1",
            "unverifiable_scope",
            "PROVIDER_RECEIPT_SEMANTICS_MISSING",
            "provider receipt semantics are not pinned",
            evidence=("body.contract_pins.provider_receipt_semantics",),
        )
        claims[invalid.name] = invalid
        return claims
    material_paths = fact_profile.get("material_request_fact_paths", [])
    try:
        authorized_request = _pointer(facts, material_paths[0])
    except (IndexError, KeyError):
        authorized_request = None
    ordered = sorted(
        (receipt for receipt in receipts if isinstance(receipt, Mapping)),
        key=lambda receipt: int(receipt.get("receipt_sequence") or 0),
    )
    previous: Mapping[str, Any] | None = None
    allowed = semantics.get("allowed_transitions")
    for index, receipt in enumerate(ordered):
        if (
            receipt.get("source_class") == "keel_transport_observation"
            and receipt.get("state") not in {"dispatched", "outcome_unknown"}
        ):
            claims["provider.receipt_state.v1"] = _assessment(
                "provider.receipt_state.v1",
                "disproved",
                "PROVIDER_RECEIPT_SOURCE_CEILING",
                "a Keel transport observation cannot assert a provider state",
                evidence=(f"body.provider_receipts[{index}]",),
            )
            claims["provider.accepted.v1"] = _assessment(
                "provider.accepted.v1",
                "disproved",
                "PROVIDER_RECEIPT_SOURCE_CEILING",
                "a Keel transport observation cannot establish provider acceptance",
                evidence=(f"body.provider_receipts[{index}]",),
            )
            return claims
        try:
            _validate_schema(receipt, "provider-receipt-v1.schema.json")
        except jsonschema.ValidationError as exc:
            claims["provider.receipt_state.v1"] = _assessment(
                "provider.receipt_state.v1",
                "disproved",
                (
                    "PROVIDER_RECEIPT_SOURCE_CEILING"
                    if "keel_transport_observation" in str(exc)
                    else "PROVIDER_RECEIPT_SCHEMA_INVALID"
                ),
                f"provider receipt schema validation failed: {exc.message}",
                evidence=(f"body.provider_receipts[{index}]",),
            )
            return claims
        identity_pairs = (
            (receipt.get("permit_id"), body.get("permit_id")),
            (receipt.get("project_id"), body.get("project_id")),
            (receipt.get("semantic_id"), binding.get("semantic_id")),
            (receipt.get("operation"), binding.get("operation")),
            (receipt.get("exact_request_digest"), authorized_request),
        )
        if any(actual != expected for actual, expected in identity_pairs):
            claims["provider.receipt_state.v1"] = _assessment(
                "provider.receipt_state.v1",
                "disproved",
                "PROVIDER_RECEIPT_BINDING_MISMATCH",
                "provider receipt identity does not match the exact Permit",
                evidence=(f"body.provider_receipts[{index}]",),
            )
            return claims
        sequence = int(receipt.get("receipt_sequence") or 0)
        if sequence != index + 1:
            claims["provider.receipt_state.v1"] = _assessment(
                "provider.receipt_state.v1",
                "disproved",
                "PROVIDER_RECEIPT_CHAIN_INVALID",
                "provider receipt sequence is not contiguous",
                evidence=(f"body.provider_receipts[{index}]",),
            )
            return claims
        if previous is None:
            if receipt.get("previous_receipt_digest") is not None:
                claims["provider.receipt_state.v1"] = _assessment(
                    "provider.receipt_state.v1",
                    "disproved",
                    "PROVIDER_RECEIPT_CHAIN_INVALID",
                    "first provider receipt has a predecessor digest",
                )
                return claims
        else:
            if receipt.get("previous_receipt_digest") != _jcs_digest(previous):
                claims["provider.receipt_state.v1"] = _assessment(
                    "provider.receipt_state.v1",
                    "disproved",
                    "PROVIDER_RECEIPT_CHAIN_INVALID",
                    "provider receipt predecessor digest does not match",
                )
                return claims
            prior_state = str(previous.get("state") or "")
            next_state = str(receipt.get("state") or "")
            transitions = (
                allowed.get(prior_state, []) if isinstance(allowed, Mapping) else []
            )
            if next_state not in transitions:
                claims["provider.receipt_state.v1"] = _assessment(
                    "provider.receipt_state.v1",
                    "disproved",
                    "PROVIDER_RECEIPT_TRANSITION_INVALID",
                    f"provider state transition {prior_state}->{next_state} is invalid",
                )
                return claims
        previous = receipt
    latest = ordered[-1]
    latest_state = str(latest.get("state") or "")
    source = str(latest.get("source_class") or "")
    claims["provider.receipt_state.v1"] = _assessment(
        "provider.receipt_state.v1",
        "supported",
        "PROVIDER_RECEIPT_STATE_VERIFIED",
        f"provider receipt chain is valid through state {latest_state}",
        evidence=("body.provider_receipts",),
    )
    claims["provider.rejected.v1"] = _assessment(
        "provider.rejected.v1",
        "supported" if latest_state == "rejected" else "insufficient_evidence",
        (
            "PROVIDER_REJECTION_VERIFIED"
            if latest_state == "rejected"
            else "PROVIDER_REJECTION_NOT_REPORTED"
        ),
        (
            "provider evidence reports rejection"
            if latest_state == "rejected"
            else "provider evidence does not report rejection"
        ),
        evidence=("body.provider_receipts",),
    )
    accepted_states = {"accepted", "running", "completed", "failed", "rolled_back"}
    authoritative = source != "keel_transport_observation"
    if latest_state in accepted_states and not authoritative:
        claims["provider.accepted.v1"] = _assessment(
            "provider.accepted.v1",
            "disproved",
            "PROVIDER_RECEIPT_SOURCE_CEILING",
            "a Keel transport observation cannot establish provider acceptance",
        )
    else:
        claims["provider.accepted.v1"] = _assessment(
            "provider.accepted.v1",
            (
                "supported"
                if latest_state in accepted_states and authoritative
                else "insufficient_evidence"
            ),
            (
                "PROVIDER_ACCEPTANCE_VERIFIED"
                if latest_state in accepted_states and authoritative
                else "PROVIDER_ACCEPTANCE_NOT_ESTABLISHED"
            ),
            (
                "authoritative provider evidence reports acceptance"
                if latest_state in accepted_states and authoritative
                else "provider acceptance is not established"
            ),
            evidence=("body.provider_receipts",),
            does_not_establish=(
                "provider completion",
                "external real-world outcome",
            ),
        )
    completed = latest_state in {"completed", "rolled_back"} and authoritative
    claims["provider.completed.v1"] = _assessment(
        "provider.completed.v1",
        "supported" if completed else "insufficient_evidence",
        (
            "PROVIDER_COMPLETION_REPORTED"
            if completed
            else "PROVIDER_COMPLETION_NOT_REPORTED"
        ),
        (
            "provider evidence reports its completed state"
            if completed
            else "provider completion is not reported"
        ),
        evidence=("body.provider_receipts",),
        does_not_establish=(
            "independent truth of a provider assertion",
            "external real-world outcome without independently verified evidence",
        ),
    )
    return claims


def adjudicate_permit_exact_v2_body(
    body: Mapping[str, Any],
    *,
    decision_verdict: str,
    signed_artifact_verifier: SignedArtifactVerifier | None = None,
    revocation_scope_faithful: bool = False,
    effective_revocation_at: datetime | None = None,
    bounded_use_scope_faithful: bool = False,
    matching_accepted_dispatches: int | None = None,
) -> PermitExactV2Result:
    """Adjudicate every declared v2 claim without silently dropping failures."""

    declared_raw = body.get("declared_claims")
    declared = (
        [str(name) for name in declared_raw if isinstance(name, str)]
        if isinstance(declared_raw, list)
        else []
    )
    permit_id = str(body.get("permit_id") or "")
    project_id = str(body.get("project_id") or "")
    assessments: dict[str, ExactClaimAssessment] = {}

    def fail_all(error: _AdjudicationError) -> PermitExactV2Result:
        for name in declared:
            if name in _EXTERNAL_CLAIMS:
                continue
            assessments[name] = _assessment(
                name,
                error.verdict,
                error.reason_code,
                str(error),
                evidence=("body",),
            )
        return PermitExactV2Result(
            permit_id=permit_id,
            project_id=project_id,
            semantic_id=None,
            fact_profile_id=None,
            authorized_action=None,
            claims=tuple(assessments[name] for name in declared if name in assessments),
        )

    if decision_verdict != "supported":
        verdict = (
            "disproved"
            if decision_verdict == "disproved"
            else "unverifiable_scope"
            if decision_verdict == "unverifiable_scope"
            else "insufficient_evidence"
        )
        return fail_all(
            _AdjudicationError(
                verdict,
                "PERMIT_EXACT_SIGNED_DECISION_UNSUPPORTED",
                "universal exact claims require a separately supported signed Permit decision",
            )
        )
    try:
        _validate_exact_pack_schema(body)
    except jsonschema.ValidationError as exc:
        return fail_all(
            _AdjudicationError(
                "disproved",
                "PERMIT_EXACT_PACK_SCHEMA_INVALID",
                f"exact pack v2 schema validation failed: {exc.message}",
            )
        )

    binding = body.get("semantic_binding")
    facts = body.get("authorization_facts")
    assert isinstance(binding, Mapping) and isinstance(facts, Mapping)
    try:
        contracts = _resolve_contracts(body, binding=binding, facts=facts)
        jsonschema.Draft202012Validator(
            contracts.facts_schema,
            format_checker=jsonschema.FormatChecker(),
        ).validate(facts)
        _verify_privacy_profile(
            fact_registry=contracts.fact_registry,
            fact_profile=contracts.fact_profile,
            facts=facts,
        )
    except jsonschema.ValidationError as exc:
        return fail_all(
            _AdjudicationError(
                "disproved",
                "PERMIT_AUTHORIZATION_FACTS_SCHEMA_INVALID",
                f"authorization facts are invalid: {exc.message}",
            )
        )
    except _AdjudicationError as exc:
        return fail_all(exc)

    decision = body.get("permit_decision")
    canonical_payload = (
        decision.get("canonical_payload") if isinstance(decision, Mapping) else None
    )
    decision_attrs = (
        decision.get("resource_attributes_json")
        if isinstance(decision, Mapping)
        else None
    )
    if not isinstance(canonical_payload, Mapping) or not isinstance(
        decision_attrs, Mapping
    ):
        return fail_all(
            _AdjudicationError(
                "insufficient_evidence",
                "PERMIT_EXACT_SIGNED_DECISION_EVIDENCE_MISSING",
                "signed Permit decision attributes are missing",
            )
        )
    commitment = canonical_payload.get("resource_attributes_canonical_hash")
    if canonical_resource_attributes_payload(decision_attrs) != commitment:
        return fail_all(
            _AdjudicationError(
                "disproved",
                "PERMIT_EXACT_SIGNED_ATTRIBUTES_MISMATCH",
                "signed Permit resource-attribute commitment does not match",
            )
        )
    if (
        decision_attrs.get("permit_semantic_binding_v2") != binding
        or decision_attrs.get("permit_authorization_facts_v1") != facts
    ):
        return fail_all(
            _AdjudicationError(
                "disproved",
                "PERMIT_EXACT_SIGNED_ATTRIBUTES_MISMATCH",
                "semantic binding or authorization facts are not present in signed attributes",
            )
        )
    try:
        _verify_profile_classification(
            fact_profile=contracts.fact_profile,
            signed_attributes=decision_attrs,
        )
    except (KeyError, _AdjudicationError) as exc:
        error = (
            exc
            if isinstance(exc, _AdjudicationError)
            else _AdjudicationError(
                "disproved",
                "PERMIT_CLASSIFICATION_INVALID",
                "signed classification evidence is missing",
            )
        )
        return fail_all(error)

    receipt = body.get("permit_receipt")
    receipt_action = receipt.get("action") if isinstance(receipt, Mapping) else None
    receipt_attrs = (
        receipt_action.get("resource_attributes_json")
        if isinstance(receipt_action, Mapping)
        else None
    )
    receipt_matches = isinstance(receipt_attrs, Mapping) and receipt_attrs == decision_attrs
    semantic_id = str(binding.get("semantic_id") or "")
    fact_profile_id = str(binding.get("fact_profile_id") or "")
    authorized_action = str(contracts.fact_profile.get("authorized_action") or "")

    assessments["permit.type.v1"] = _assessment(
        "permit.type.v1",
        "supported",
        "PERMIT_TYPE_VERIFIED",
        "the signed Permit resolves exactly one admitted semantic and fact profile",
        evidence=(
            "body.permit_decision.resource_attributes_json",
            "body.contract_pins",
        ),
    )

    target_paths = contracts.fact_profile.get("target_fact_paths", [])
    target_values_present = isinstance(target_paths, list) and bool(target_paths)
    if target_values_present:
        try:
            for path in target_paths:
                _pointer(facts, str(path))
        except KeyError:
            target_values_present = False
    assessments["permit.exact_target.v1"] = _assessment(
        "permit.exact_target.v1",
        "supported" if target_values_present and receipt_matches else "disproved",
        (
            "PERMIT_EXACT_TARGET_VERIFIED"
            if target_values_present and receipt_matches
            else "PERMIT_EXACT_TARGET_MISMATCH"
        ),
        (
            "all required target facts are signed and schema-valid"
            if target_values_present and receipt_matches
            else "required target facts or the receipt comparison projection diverge"
        ),
        evidence=(
            "body.authorization_facts",
            "body.permit_decision.resource_attributes_json",
            "body.permit_receipt.action.resource_attributes_json",
        ),
    )

    material_paths = contracts.fact_profile.get("material_request_fact_paths", [])
    material_values: list[Any] = []
    if isinstance(material_paths, list):
        try:
            material_values = [_pointer(facts, str(path)) for path in material_paths]
        except KeyError:
            material_values = []
    dispatch_digests: list[Any] = []
    enforcement = body.get("enforcement_evidence")
    runtime_proof = (
        enforcement.get("runtime_enforcement_proof")
        if isinstance(enforcement, Mapping)
        else None
    )
    if isinstance(runtime_proof, Mapping):
        dispatch_digests.append(runtime_proof.get("exact_request_digest"))
    for transition in body.get("bounded_use_transitions", []):
        if isinstance(transition, Mapping):
            dispatch_digests.append(transition.get("exact_request_digest"))
    for provider_receipt in body.get("provider_receipts", []):
        if isinstance(provider_receipt, Mapping):
            dispatch_digests.append(provider_receipt.get("exact_request_digest"))
    material_ok = bool(material_values) and all(
        digest in material_values for digest in dispatch_digests
    )
    assessments["permit.material_request.v1"] = _assessment(
        "permit.material_request.v1",
        "supported" if material_ok else "disproved",
        (
            "PERMIT_MATERIAL_REQUEST_VERIFIED"
            if material_ok
            else "PERMIT_MATERIAL_REQUEST_MISMATCH"
        ),
        (
            "material request facts are signed and match supplied dispatch evidence"
            if material_ok
            else "material request facts are missing or diverge from dispatch evidence"
        ),
        evidence=("body.authorization_facts", "body.enforcement_evidence"),
    )

    dispatch_at: datetime | None = None
    runtime_signature_ok = False
    if isinstance(runtime_proof, Mapping):
        runtime_signature_ok, _ = _signed_artifact_status(
            runtime_proof,
            schema_name="runtime-enforcement-proof-v1.schema.json",
            purpose="runtime_enforcement_signing",
            signed_at_field="evaluated_at",
            verifier=signed_artifact_verifier,
        )
        if runtime_signature_ok:
            dispatch_at = _parse_time(runtime_proof.get("evaluated_at"))
    if dispatch_at is None:
        transitions = body.get("bounded_use_transitions")
        if isinstance(transitions, list) and transitions:
            first = transitions[0]
            if isinstance(first, Mapping):
                signed, _ = _signed_artifact_status(
                    first,
                    schema_name="permit-bounded-use-v1.schema.json",
                    purpose="permit_bounded_use_signing",
                    signed_at_field="occurred_at",
                    verifier=signed_artifact_verifier,
                )
                if signed:
                    dispatch_at = _parse_time(first.get("occurred_at"))
    issued_at = _parse_time(canonical_payload.get("issued_at"))
    expires_at = _parse_time(canonical_payload.get("expires_at"))
    if dispatch_at is None or issued_at is None or expires_at is None:
        assessments["permit.valid_at_dispatch.v1"] = _assessment(
            "permit.valid_at_dispatch.v1",
            "insufficient_evidence",
            "PERMIT_DISPATCH_INSTANT_UNTRUSTED",
            "a trusted dispatch instant and signed Permit validity window are required",
        )
    elif not (issued_at <= dispatch_at < expires_at):
        assessments["permit.valid_at_dispatch.v1"] = _assessment(
            "permit.valid_at_dispatch.v1",
            "disproved",
            "PERMIT_EXPIRED_AT_DISPATCH",
            "dispatch is outside the signed Permit validity window",
        )
    else:
        assessments["permit.valid_at_dispatch.v1"] = _assessment(
            "permit.valid_at_dispatch.v1",
            "supported",
            "PERMIT_VALID_AT_DISPATCH",
            "dispatch occurred inside the signed Permit validity window",
        )

    if not revocation_scope_faithful or dispatch_at is None:
        assessments["permit.revocation_at_dispatch.v1"] = _assessment(
            "permit.revocation_at_dispatch.v1",
            "unverifiable_scope",
            "PERMIT_REVOCATION_SCOPE_UNVERIFIED",
            "scope-faithful revocation evidence through dispatch is required",
        )
    elif (
        effective_revocation_at is not None
        and effective_revocation_at <= dispatch_at
    ):
        assessments["permit.revocation_at_dispatch.v1"] = _assessment(
            "permit.revocation_at_dispatch.v1",
            "disproved",
            "PERMIT_REVOKED_AT_DISPATCH",
            "an effective Permit revocation preceded dispatch",
        )
    else:
        assessments["permit.revocation_at_dispatch.v1"] = _assessment(
            "permit.revocation_at_dispatch.v1",
            "supported",
            "PERMIT_NOT_REVOKED_AT_DISPATCH",
            "no effective Permit revocation preceded dispatch in the verified scope",
        )

    boundary_ok = False
    boundary_reason = "certified enforcement evidence is missing"
    if isinstance(enforcement, Mapping):
        certification = enforcement.get("adapter_certification")
        deployment = enforcement.get("deployment_assurance")
        if all(
            isinstance(item, Mapping)
            for item in (certification, deployment, runtime_proof)
        ):
            assert isinstance(certification, Mapping)
            assert isinstance(deployment, Mapping)
            assert isinstance(runtime_proof, Mapping)
            cert_ok, cert_error = _signed_artifact_status(
                certification,
                schema_name="adapter-certification-v1.schema.json",
                purpose="adapter_certification_signing",
                signed_at_field="issued_at",
                verifier=signed_artifact_verifier,
            )
            deployment_ok, deployment_error = _signed_artifact_status(
                deployment,
                schema_name="deployment-assurance-v1.schema.json",
                purpose="deployment_assurance_signing",
                signed_at_field="verified_at",
                verifier=signed_artifact_verifier,
            )
            runtime_ok, runtime_error = _signed_artifact_status(
                runtime_proof,
                schema_name="runtime-enforcement-proof-v1.schema.json",
                purpose="runtime_enforcement_signing",
                signed_at_field="evaluated_at",
                verifier=signed_artifact_verifier,
            )
            if not all((cert_ok, deployment_ok, runtime_ok)):
                boundary_reason = "; ".join(
                    value
                    for value in (cert_error, deployment_error, runtime_error)
                    if value
                )
            else:
                cert_hash = certification.get("canonical_hash")
                deployment_hash = deployment.get("canonical_hash")
                identity_ok = all(
                    (
                        deployment.get("adapter_certification_id")
                        == certification.get("certification_id"),
                        deployment.get("adapter_certification_digest") == cert_hash,
                        runtime_proof.get("adapter_certification_id")
                        == certification.get("certification_id"),
                        runtime_proof.get("adapter_certification_digest") == cert_hash,
                        runtime_proof.get("deployment_assurance_id")
                        == deployment.get("assurance_id"),
                        runtime_proof.get("deployment_assurance_digest")
                        == deployment_hash,
                        deployment.get("project_id") == project_id,
                        runtime_proof.get("project_id") == project_id,
                        runtime_proof.get("permit_id") == permit_id,
                        runtime_proof.get("semantic_id") == semantic_id,
                        semantic_id in certification.get("semantic_ids", []),
                        semantic_id in deployment.get("semantic_ids", []),
                        binding.get("governed_surface")
                        in certification.get("governed_surfaces", []),
                        deployment.get("governed_surface")
                        == binding.get("governed_surface"),
                        deployment.get("adapter_id") == certification.get("adapter_id"),
                        deployment.get("adapter_version")
                        == certification.get("adapter_version"),
                        runtime_proof.get("exact_request_digest") in material_values,
                    )
                )
                if not identity_ok:
                    boundary_reason = "certification artifact identities or digests diverge"
                else:
                    boundary_time = _parse_time(runtime_proof.get("evaluated_at"))
                    cert_start = _parse_time(certification.get("issued_at"))
                    cert_end = _parse_time(certification.get("expires_at"))
                    deployment_start = _parse_time(deployment.get("verified_at"))
                    deployment_end = _parse_time(deployment.get("expires_at"))
                    cert_revoked = _parse_time(certification.get("revoked_at"))
                    deployment_revoked = _parse_time(deployment.get("revoked_at"))
                    active = (
                        boundary_time is not None
                        and cert_start is not None
                        and cert_end is not None
                        and deployment_start is not None
                        and deployment_end is not None
                        and cert_start <= boundary_time < cert_end
                        and deployment_start <= boundary_time < deployment_end
                        and (
                            cert_revoked is None or boundary_time < cert_revoked
                        )
                        and (
                            deployment_revoked is None
                            or boundary_time < deployment_revoked
                        )
                    )
                    expected_decision = str(
                        body.get("decision_state", {}).get("decision") or ""
                    )
                    if expected_decision == "challenge":
                        expected_decision = "review"
                    if not active:
                        boundary_reason = "certification was not active at dispatch"
                    elif runtime_proof.get("gate_result") != expected_decision:
                        boundary_reason = "runtime gate result does not match decision"
                    else:
                        boundary_ok = True
    assessments["permit.enforced_at_certified_boundary.v1"] = _assessment(
        "permit.enforced_at_certified_boundary.v1",
        "supported" if boundary_ok else (
            "insufficient_evidence"
            if "missing" in boundary_reason or "unavailable" in boundary_reason
            else "disproved"
        ),
        (
            "CERTIFIED_BOUNDARY_VERIFIED"
            if boundary_ok
            else "CERTIFICATION_NOT_ACTIVE_AT_DISPATCH"
            if "not active" in boundary_reason
            else "CERTIFICATION_BINDING_MISMATCH"
        ),
        (
            "the exact request crossed an active certified pre-effect boundary"
            if boundary_ok
            else boundary_reason
        ),
        evidence=("body.enforcement_evidence",),
    )

    transitions = [
        transition
        for transition in body.get("bounded_use_transitions", [])
        if isinstance(transition, Mapping)
    ]
    maximum_uses = _signed_maximum_uses(canonical_payload)
    bounded_ok = bool(transitions) and maximum_uses is not None
    bounded_reason = "signed bounded-use evidence is missing"
    previous_transition: Mapping[str, Any] | None = None
    idempotency_bindings: dict[str, tuple[Any, ...]] = {}
    if transitions:
        for index, transition in enumerate(
            sorted(transitions, key=lambda item: int(item.get("counter_sequence") or 0))
        ):
            signed, signed_error = _signed_artifact_status(
                transition,
                schema_name="permit-bounded-use-v1.schema.json",
                purpose="permit_bounded_use_signing",
                signed_at_field="occurred_at",
                verifier=signed_artifact_verifier,
            )
            if not signed:
                bounded_ok = False
                bounded_reason = signed_error or "bounded-use signature is invalid"
                break
            sequence = int(transition.get("counter_sequence") or 0)
            if (
                sequence != index + 1
                or transition.get("permit_id") != permit_id
                or transition.get("project_id") != project_id
                or transition.get("maximum_uses") != maximum_uses
                or transition.get("consumed_before") != index
                or transition.get("consumed_after") != index + 1
                or transition.get("exact_request_digest") not in material_values
            ):
                bounded_ok = False
                bounded_reason = "bounded-use transition identity or sequence diverges"
                break
            if previous_transition is not None and transition.get(
                "previous_transition_digest"
            ) != previous_transition.get("canonical_hash"):
                bounded_ok = False
                bounded_reason = "bounded-use predecessor digest diverges"
                break
            if int(transition.get("consumed_after") or 0) > maximum_uses:
                bounded_ok = False
                bounded_reason = "bounded-use maximum was exceeded"
                break
            commitment = transition.get("idempotency_key_commitment")
            digest = (
                str(commitment.get("digest") or "")
                if isinstance(commitment, Mapping)
                else ""
            )
            identity = (
                permit_id,
                transition.get("exact_request_digest"),
                transition.get("dispatch_id"),
            )
            if digest in idempotency_bindings and idempotency_bindings[digest] != identity:
                bounded_ok = False
                bounded_reason = "idempotency commitment was rebound"
                break
            idempotency_bindings[digest] = identity
            previous_transition = transition
    assessments["permit.bounded_use.v1"] = _assessment(
        "permit.bounded_use.v1",
        "supported" if bounded_ok else (
            "insufficient_evidence"
            if maximum_uses is None or not transitions
            else "disproved"
        ),
        (
            "BOUNDED_USE_VERIFIED"
            if bounded_ok
            else "BOUNDED_USE_LIMIT_EXCEEDED"
            if "maximum" in bounded_reason
            else "BOUNDED_USE_EVIDENCE_INVALID"
        ),
        (
            "signed monotonic bounded-use transitions stay within the Permit limit"
            if bounded_ok
            else bounded_reason
        ),
        evidence=("body.bounded_use_transitions",),
    )
    if maximum_uses != 1:
        assessments["permit.single_use.v1"] = _assessment(
            "permit.single_use.v1",
            "disproved" if maximum_uses is not None else "insufficient_evidence",
            "SINGLE_USE_POPULATION_MISMATCH",
            "the signed Permit does not establish maximum_uses=1",
        )
    elif not bounded_use_scope_faithful:
        assessments["permit.single_use.v1"] = _assessment(
            "permit.single_use.v1",
            "unverifiable_scope",
            "SINGLE_USE_SCOPE_UNVERIFIED",
            "scope-faithful bounded-use population evidence is required",
        )
    else:
        assessments["permit.single_use.v1"] = _assessment(
            "permit.single_use.v1",
            "supported" if bounded_ok and len(transitions) == 1 else "disproved",
            (
                "SINGLE_USE_VERIFIED"
                if bounded_ok and len(transitions) == 1
                else "SINGLE_USE_POPULATION_MISMATCH"
            ),
            "single-use population contains exactly one valid transition",
        )
    if matching_accepted_dispatches is None:
        assessments["permit.replay_prevented.v1"] = _assessment(
            "permit.replay_prevented.v1",
            "unverifiable_scope",
            "PERMIT_REPLAY_SCOPE_UNVERIFIED",
            "scope-faithful dispatch population evidence is required",
        )
    else:
        assessments["permit.replay_prevented.v1"] = _assessment(
            "permit.replay_prevented.v1",
            "supported" if matching_accepted_dispatches <= 1 else "disproved",
            (
                "PERMIT_REPLAY_PREVENTION_VERIFIED"
                if matching_accepted_dispatches <= 1
                else "PERMIT_REPLAY_DETECTED"
            ),
            (
                "no repeated accepted dispatch was found in the verified scope"
                if matching_accepted_dispatches <= 1
                else "multiple accepted dispatches share the same Permit and request identity"
            ),
        )
    idempotency_ok = bounded_ok and len(idempotency_bindings) == len(transitions)
    assessments["permit.idempotency_bound.v1"] = _assessment(
        "permit.idempotency_bound.v1",
        "supported" if idempotency_ok else (
            "insufficient_evidence" if not transitions else "disproved"
        ),
        (
            "PERMIT_IDEMPOTENCY_BOUND"
            if idempotency_ok
            else "PERMIT_IDEMPOTENCY_BINDING_MISMATCH"
        ),
        (
            "each idempotency commitment binds one Permit, request, and dispatch"
            if idempotency_ok
            else "idempotency binding evidence is absent or inconsistent"
        ),
    )

    assessments.update(
        _provider_receipt_claims(
            body=body,
            facts=facts,
            binding=binding,
            fact_profile=contracts.fact_profile,
            semantics=contracts.provider_receipt_semantics,
        )
    )
    for name in declared:
        if name in _EXTERNAL_CLAIMS or name in assessments:
            continue
        assessments[name] = _assessment(
            name,
            "unverifiable_scope",
            "PERMIT_EXACT_DECLARED_CLAIM_UNSUPPORTED",
            "this verifier does not implement the declared exact-pack claim",
        )
    return PermitExactV2Result(
        permit_id=permit_id,
        project_id=project_id,
        semantic_id=semantic_id,
        fact_profile_id=fact_profile_id,
        authorized_action=authorized_action,
        claims=tuple(assessments[name] for name in declared if name in assessments),
    )


__all__ = [
    "PROFILE",
    "PROFILE_VERSION",
    "UNIVERSAL_CLAIMS",
    "ExactClaimAssessment",
    "PermitExactV2Result",
    "adjudicate_permit_exact_v2_body",
]
