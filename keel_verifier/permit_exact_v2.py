"""Fact-profile-driven adjudication for exact-pack v2 and v3 bodies.

The signed Permit decision is the authority source. Embedded contracts are
replay inputs, receipt fields are comparison projections, and every declared
universal claim receives a structured result even when its evidence is absent.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
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
PROFILE_V3 = "keel.permit_exact/v3"
PROFILE_V3_VERSION = 3
SUPPORTED_PROFILES = {
    PROFILE: PROFILE_VERSION,
    PROFILE_V3: PROFILE_V3_VERSION,
}
_DATA_ROOT = "data/permit_to_x"
_CLAIM_REGISTRY_IDS = {
    "verifier-claims.v2": "keel.verifier_claim_registry.v2",
    "verifier-claims.v3": "keel.verifier_claim_registry.v3",
    "verifier-claims.v4": "keel.verifier_claim_registry.v4",
    "verifier-claims.v5": "keel.verifier_claim_registry.v5",
}
_UNIVERSAL_SEMANTICS_IDS = {
    "v1": "keel.permit.universal_verification.v1",
    "v2": "keel.permit.universal_verification.v2",
    "v3": "keel.permit.universal_verification.v3",
    "v4": "keel.permit.universal_verification.v4",
}
_PROVIDER_RECEIPT_SEMANTICS_ID = "keel.provider.receipt_state.v1"
DELEGATE_CHILD_LINKAGE_CLAIM = "permit.delegate_child_linkage.v1"
GENERATE_TEXT_EXACT_REQUEST_CLAIM = "permit.generate_text_exact_request.v1"
REFUND_ORIGINAL_PAYMENT_BOUND_CLAIM = (
    "permit.refund_original_payment_bound.v1"
)
ENFORCEMENT_REGIME_AT_ISSUANCE_CLAIM = (
    "permit.enforcement_regime_at_issuance.v1"
)
ENFORCEMENT_REGIME_AT_DISPATCH_CLAIM = (
    "permit.enforcement_regime_at_dispatch.v1"
)
ENFORCEMENT_REGIME_CLAIMS = (
    ENFORCEMENT_REGIME_AT_ISSUANCE_CLAIM,
    ENFORCEMENT_REGIME_AT_DISPATCH_CLAIM,
)
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
    verifier_safe_facts: dict[str, Any] = field(default_factory=dict)
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


def _verify_trusted_preflight_window(
    *,
    facts: Mapping[str, Any],
    canonical_payload: Mapping[str, Any],
) -> None:
    """Require a fresh gateway snapshot at the signed authorization instant."""

    if facts.get("version") not in {
        "keel.payment_ledger_exact_facts.v1",
        "keel.transactional_cx_exact_facts.v1",
        "keel.release_exact_facts.v1",
        "keel.identity_security_exact_facts.v1",
        "keel.coding_workspace_exact_facts.v1",
    }:
        return
    issued_at = _parse_time(canonical_payload.get("issued_at"))
    observed_at = _parse_time(facts.get("preflight_observed_at"))
    expires_at = _parse_time(facts.get("preflight_expires_at"))
    if (
        issued_at is None
        or observed_at is None
        or expires_at is None
        or observed_at > issued_at
        or issued_at >= expires_at
        or expires_at - observed_at > timedelta(minutes=5)
    ):
        raise _AdjudicationError(
            "disproved",
            "PERMIT_PREFLIGHT_WINDOW_INVALID",
            "the gateway-signed preflight snapshot was not fresh at authorization",
        )


def _verify_transactional_cx_invariants(facts: Mapping[str, Any]) -> None:
    """Adjudicate CX relations that JSON Schema cannot express."""

    if facts.get("version") != "keel.transactional_cx_exact_facts.v1":
        return
    action = facts.get("action")
    valid = True
    if action == "payment.refund":
        amount = facts.get("amount_minor")
        remaining = facts.get("refundable_amount_minor_before")
        valid = (
            isinstance(amount, int)
            and not isinstance(amount, bool)
            and isinstance(remaining, int)
            and not isinstance(remaining, bool)
            and amount <= remaining
            and facts.get("refund_application_fee") is False
            and facts.get("reverse_transfer") is False
        )
    elif action == "customer.credit.issue":
        amount = facts.get("amount_minor")
        provider_amount = facts.get("provider_amount_minor")
        before = facts.get("customer_balance_before_minor")
        after = facts.get("expected_customer_balance_after_minor")
        valid = (
            isinstance(amount, int)
            and not isinstance(amount, bool)
            and isinstance(provider_amount, int)
            and not isinstance(provider_amount, bool)
            and isinstance(before, int)
            and not isinstance(before, bool)
            and isinstance(after, int)
            and not isinstance(after, bool)
            and provider_amount == -amount
            and after == before - amount
        )
    elif action == "subscription.cancellation.schedule":
        valid = (
            facts.get("cancel_at_period_end_before") is False
            and facts.get("cancel_at_period_end_requested") is True
        )
    elif action == "subscription.cancellation.withdraw":
        valid = (
            facts.get("cancel_at_period_end_before") is True
            and facts.get("cancel_at_period_end_requested") is False
            and facts.get("canceled_at_before") is None
            and facts.get("ended_at_before") is None
        )
    elif action == "support.case.resolve":
        valid = (
            facts.get("current_stage_state") == "OPEN"
            and facts.get("requested_stage_state") == "CLOSED"
        )
    else:
        valid = False
    if not valid:
        raise _AdjudicationError(
            "disproved",
            "PERMIT_TRANSACTIONAL_CX_INVARIANT_INVALID",
            "the signed Transactional CX facts violate an exact provider-action invariant",
        )


def _verify_release_invariants(facts: Mapping[str, Any]) -> None:
    """Adjudicate release relations that JSON Schema cannot express."""

    if facts.get("version") != "keel.release_exact_facts.v1":
        return
    action = facts.get("action")
    valid = True
    if action == "repository.pull_request.merge":
        required = facts.get("required_approving_reviews")
        observed = facts.get("observed_approving_reviews")
        valid = (
            isinstance(required, int)
            and not isinstance(required, bool)
            and isinstance(observed, int)
            and not isinstance(observed, bool)
            and observed >= required
            and facts.get("required_status_checks_count", 0) >= 1
            and facts.get("required_status_checks_state") == "success"
            and facts.get("pull_request_state") == "open"
            and facts.get("draft") is False
            and facts.get("mergeable") is True
            and facts.get("mergeable_state") == "clean"
        )
    elif action == "deployment.commit.deploy":
        valid = (
            facts.get("artifact_revision_sha") == facts.get("source_commit_sha")
            and facts.get("current_image_digest") != facts.get("target_image_digest")
            and facts.get("current_config_digest") != facts.get("target_config_digest")
            and facts.get("source_commit_signature_verified") is True
            and facts.get("artifact_revision_matches_source_commit") is True
        )
    elif action == "deployment.rollback":
        valid = (
            facts.get("current_image_digest")
            != facts.get("rollback_target_image_digest")
            and facts.get("current_config_digest")
            != facts.get("rollback_target_config_digest")
            and facts.get("current_release_instance_id")
            != facts.get("prior_release_instance_id")
        )
    else:
        valid = False
    if not valid:
        raise _AdjudicationError(
            "disproved",
            "PERMIT_RELEASE_INVARIANT_INVALID",
            "the signed release facts violate an exact provider-action invariant",
        )


def _verify_identity_security_invariants(facts: Mapping[str, Any]) -> None:
    """Adjudicate identity/security relations JSON Schema cannot express."""

    if facts.get("version") != "keel.identity_security_exact_facts.v1":
        return
    action = facts.get("action")
    valid = True
    if action == "identity.mfa.reset":
        valid = (
            isinstance(facts.get("enrolled_factor_count"), int)
            and not isinstance(facts.get("enrolled_factor_count"), bool)
            and facts.get("enrolled_factor_count", 0) >= 1
            and facts.get("reset_scope") == "all_enrolled_factors"
        )
    elif action == "identity.sessions.revoke":
        valid = (
            facts.get("revoke_oauth_tokens") is True
            and facts.get("active_sessions_enumerable") is False
        )
    elif action == "identity.disable":
        valid = (
            facts.get("current_user_status") == "ACTIVE"
            and facts.get("target_user_status") == "DEPROVISIONED"
            and facts.get("destructive_deprovisioning_acknowledged") is True
        )
    elif action in {
        "identity.group_access.grant",
        "identity.group_access.remove",
    }:
        current_count = facts.get("current_group_member_count")
        projected_count = facts.get("projected_group_member_count")
        counts_are_ints = (
            isinstance(current_count, int)
            and not isinstance(current_count, bool)
            and isinstance(projected_count, int)
            and not isinstance(projected_count, bool)
        )
        if action == "identity.group_access.grant":
            valid = (
                counts_are_ints
                and facts.get("current_membership") is False
                and facts.get("target_membership") is True
                and projected_count == current_count + 1
            )
        else:
            valid = (
                counts_are_ints
                and facts.get("current_membership") is True
                and facts.get("target_membership") is False
                and facts.get("target_is_last_privileged_member") is False
                and projected_count == current_count - 1
            )
    elif action == "security.indicator.block":
        current_count = facts.get("current_rules_count")
        projected_count = facts.get("projected_rules_count")
        valid = (
            isinstance(current_count, int)
            and not isinstance(current_count, bool)
            and isinstance(projected_count, int)
            and not isinstance(projected_count, bool)
            and facts.get("zone_status") == "active"
            and facts.get("current_matching_rule_count") == 0
            and facts.get("target_action") == "block"
            and facts.get("rule_enabled") is True
            and projected_count == current_count + 1
        )
    else:
        valid = False
    if not valid:
        raise _AdjudicationError(
            "disproved",
            "PERMIT_IDENTITY_SECURITY_INVARIANT_INVALID",
            "the signed identity/security facts violate an exact provider-action invariant",
        )


def _verify_coding_workspace_invariants(facts: Mapping[str, Any]) -> None:
    """Adjudicate Coding Workspace relations JSON Schema cannot express."""

    if facts.get("version") != "keel.coding_workspace_exact_facts.v1":
        return
    action = facts.get("action")
    valid = True
    if action == "code.package.install":
        valid = (
            facts.get("connector_identity") == "npm"
            and facts.get("workspace_is_disposable") is True
            and facts.get("package_allowlisted") is True
            and facts.get("registry_origin") == "https://registry.npmjs.org"
            and facts.get("target_dependency_version")
            != facts.get("current_dependency_version")
            and facts.get("package_lock_present") is True
            and facts.get("install_mode") == "save_exact"
            and facts.get("lifecycle_scripts_disabled") is True
        )
    elif action == "repository.branch.push":
        valid = (
            facts.get("connector_identity") == "github"
            and facts.get("base_branch_protected") is True
            and facts.get("target_branch_exists") is False
            and facts.get("target_branch_protected") is False
            and facts.get("base_branch") != facts.get("target_branch")
            and facts.get("protected_path_change_count") == 0
            and facts.get("push_mode") == "create_ref_only"
            and facts.get("force_push") is False
        )
    elif action == "repository.pull_request.create":
        valid = (
            facts.get("connector_identity") == "github"
            and facts.get("head_ref_exists") is True
            and facts.get("base_branch_protected") is True
            and facts.get("same_repository") is True
            and facts.get("head_branch") != facts.get("base_branch")
            and facts.get("head_commit_sha") != facts.get("base_commit_sha")
            and facts.get("compare_status") == "ahead"
            and facts.get("ahead_by", 0) >= 1
            and facts.get("changed_files_count", 0) >= 1
            and facts.get("protected_path_change_count") == 0
            and facts.get("existing_open_pull_request_count") == 0
            and facts.get("merge_authorized") is False
        )
    else:
        valid = False
    if not valid:
        raise _AdjudicationError(
            "disproved",
            "PERMIT_CODING_WORKSPACE_INVARIANT_INVALID",
            "the signed Coding Workspace facts violate an exact provider-action invariant",
        )


def _verifier_safe_facts(
    fact_profile: Mapping[str, Any], facts: Mapping[str, Any]
) -> dict[str, Any]:
    """Project only fields the pinned profile marks verifier-safe."""

    projected = {
        key: facts[key]
        for key in ("version", "fact_profile_id", "action")
        if key in facts
    }
    fields = fact_profile.get("fields")
    if not isinstance(fields, list):
        return projected
    for field_spec in fields:
        if not isinstance(field_spec, Mapping):
            continue
        disclosure = field_spec.get("disclosure")
        path = field_spec.get("path")
        if (
            not isinstance(disclosure, Mapping)
            or disclosure.get("verifier_safe") == "omit"
            or not isinstance(path, str)
            or path.count("/") != 1
        ):
            continue
        key = path.removeprefix("/").replace("~1", "/").replace("~0", "~")
        if key in facts:
            projected[key] = facts[key]
    return projected


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
    ceilings: dict[str, tuple[str, ...]] = {}
    for registry_name in ("v2.json", "v3.json", "v4.json", "v5.json"):
        registry = _json(f"../claim_registry/{registry_name}")
        for claim in registry.get("claims", []):
            if not isinstance(claim, Mapping):
                continue
            name = claim.get("name")
            values = claim.get("does_not_establish")
            if not isinstance(name, str) or not isinstance(values, list):
                continue
            ceilings[name] = tuple(
                str(value) for value in values if isinstance(value, str)
            )
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


@lru_cache(maxsize=2)
def _schema_registry(profile: str) -> tuple[dict[str, Any], Registry]:
    pack_schema = {
        PROFILE: "schemas/permit-exact-pack-v2.schema.json",
        PROFILE_V3: "schemas/permit-exact-pack-v3.schema.json",
    }.get(profile)
    if pack_schema is None:
        raise ValueError(f"unsupported exact-pack profile: {profile}")
    names = (
        pack_schema,
        "schemas/permit-semantic-binding-v2.schema.json",
        "schemas/adapter-certification-v1.schema.json",
        "schemas/deployment-assurance-v1.schema.json",
        "schemas/runtime-enforcement-proof-v1.schema.json",
        "schemas/runtime-enforcement-proof-v2.schema.json",
        "schemas/permit-enforcement-state-v1.schema.json",
        "schemas/permit-bounded-use-v1.schema.json",
        "schemas/permit-selective-disclosure-v1.schema.json",
        "schemas/provider-receipt-v1.schema.json",
        "schemas/delegate-child-linkage-v1.schema.json",
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
    profile = str(body.get("profile") or "")
    expected_version = SUPPORTED_PROFILES.get(profile)
    if expected_version is None or body.get("profile_version") != expected_version:
        raise jsonschema.ValidationError(
            f"unsupported exact-pack profile identity: {profile}"
        )
    schema, registry = _schema_registry(profile)
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
    bundled_path: str | tuple[str, ...],
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
    paths = (bundled_path,) if isinstance(bundled_path, str) else bundled_path
    if not any(raw == _bytes(path) for path in paths):
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


def _compose_universal_semantics(
    payload: Mapping[str, Any],
    *,
    source: str,
) -> dict[str, Any]:
    """Resolve a digest-pinned universal-recipe extension chain.

    Extension artifacts intentionally contain only their deltas. Adjudication
    must compose the pinned base bodies before consulting consequence or
    evidence requirements; treating v4 as a replacement would silently drop
    the v2/v3 consequence rules.
    """

    extension = payload.get("extends")
    if not isinstance(extension, Mapping):
        return dict(payload)
    artifact_id = extension.get("artifact_id")
    version = extension.get("version")
    expected_digest = extension.get("sha256")
    if (
        not isinstance(artifact_id, str)
        or artifact_id != _UNIVERSAL_SEMANTICS_IDS.get(str(version or ""))
        or not isinstance(expected_digest, str)
    ):
        raise _AdjudicationError(
            "unverifiable_scope",
            "PERMIT_CONTRACT_PIN_UNSUPPORTED",
            f"universal semantics at {source} has an unsupported base",
        )
    base_path = f"../semantics/permit/universal_verification_{version}.json"
    try:
        base_raw = _bytes(base_path)
        base = json.loads(base_raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise _AdjudicationError(
            "unverifiable_scope",
            "PERMIT_CONTRACT_PIN_UNSUPPORTED",
            f"could not load the universal semantics base for {source}",
        ) from exc
    actual_digest = hashlib.sha256(base_raw).hexdigest()
    if actual_digest != expected_digest:
        raise _AdjudicationError(
            "disproved",
            "PERMIT_CONTRACT_PIN_DIGEST_MISMATCH",
            f"universal semantics at {source} does not match its pinned base",
        )
    if base.get("id") != artifact_id or base.get("version") != version:
        raise _AdjudicationError(
            "disproved",
            "PERMIT_CONTRACT_PIN_ID_MISMATCH",
            f"universal semantics at {source} names the wrong base",
        )
    composed_base = _compose_universal_semantics(base, source=base_path)
    base_body = composed_base.get("body")
    child_body = payload.get("body")
    if not isinstance(base_body, Mapping) or not isinstance(child_body, Mapping):
        raise _AdjudicationError(
            "unverifiable_scope",
            "PERMIT_CONTRACT_PIN_UNSUPPORTED",
            f"universal semantics at {source} has an invalid body",
        )
    merged_body: dict[str, Any] = dict(base_body)
    for key, value in child_body.items():
        existing = merged_body.get(key)
        if isinstance(existing, Mapping) and isinstance(value, Mapping):
            merged_body[key] = {**existing, **value}
        else:
            merged_body[key] = value
    return {**dict(payload), "body": merged_body}


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
        bundled_path=(
            "../claim_registry/v2.json",
            "../claim_registry/v3.json",
            "../claim_registry/v4.json",
            "../claim_registry/v5.json",
        ),
        artifact_id=None,
    )
    selector_registry, selector_digest = _decode_pin(
        pins.get("semantic_selector_registry"),
        label="semantic selector registry",
        bundled_path=(
            "semantic_registry/v3.json",
            "semantic_registry/v4.json",
            "semantic_registry/v5.json",
            "semantic_registry/v6.json",
            "semantic_registry/v7.json",
            "semantic_registry/v8.json",
            "semantic_registry/v9.json",
            "semantic_registry/v10.json",
            "semantic_registry/v11.json",
        ),
        artifact_id="keel.permit.semantic_selector_registry",
    )
    fact_registry, fact_digest = _decode_pin(
        pins.get("fact_profile_registry"),
        label="fact profile registry",
        bundled_path=(
            "fact_profiles/v2.json",
            "fact_profiles/v3.json",
            "fact_profiles/v4.json",
            "fact_profiles/v5.json",
            "fact_profiles/v6.json",
            "fact_profiles/v7.json",
            "fact_profiles/v8.json",
            "fact_profiles/v9.json",
        ),
        artifact_id="keel.permit.fact_profile_registry",
    )
    universal_semantics, universal_digest = _decode_pin(
        pins.get("universal_semantics"),
        label="universal semantics",
        bundled_path=(
            "../semantics/permit/universal_verification_v1.json",
            "../semantics/permit/universal_verification_v2.json",
            "../semantics/permit/universal_verification_v3.json",
            "../semantics/permit/universal_verification_v4.json",
        ),
        artifact_id=None,
    )
    claim_version = str(claim_registry.get("version") or "")
    expected_claim_id = _CLAIM_REGISTRY_IDS.get(claim_version)
    claim_pin = pins.get("claim_registry")
    if expected_claim_id is None or not isinstance(claim_pin, Mapping):
        raise _AdjudicationError(
            "unverifiable_scope",
            "PERMIT_CONTRACT_PIN_UNSUPPORTED",
            "claim registry version is not supported",
        )
    if claim_pin.get("artifact_id") != expected_claim_id:
        raise _AdjudicationError(
            "disproved",
            "PERMIT_CONTRACT_PIN_ID_MISMATCH",
            "claim registry artifact identity does not match its version",
        )
    universal_version = str(universal_semantics.get("version") or "")
    expected_universal_id = _UNIVERSAL_SEMANTICS_IDS.get(universal_version)
    universal_pin = pins.get("universal_semantics")
    if expected_universal_id is None or not isinstance(universal_pin, Mapping):
        raise _AdjudicationError(
            "unverifiable_scope",
            "PERMIT_CONTRACT_PIN_UNSUPPORTED",
            "universal semantics version is not supported",
        )
    if universal_pin.get("artifact_id") != expected_universal_id:
        raise _AdjudicationError(
            "disproved",
            "PERMIT_CONTRACT_PIN_ID_MISMATCH",
            "universal semantics artifact identity does not match its version",
        )
    expected_recipe_claims = {
        "v1": "verifier-claims.v2",
        "v2": "verifier-claims.v3",
        "v3": "verifier-claims.v4",
        "v4": "verifier-claims.v5",
    }
    if universal_semantics.get("body", {}).get(
        "claim_registry_version"
    ) != expected_recipe_claims[universal_version] or claim_version != (
        expected_recipe_claims[universal_version]
    ):
        raise _AdjudicationError(
            "disproved",
            "PERMIT_CONTRACT_PIN_VERSION_MISMATCH",
            "universal semantics and claim registry versions diverge",
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
    if (
        facts.get("fact_profile_id") != fact_profile_id
        or facts.get("action") != fact_profile.get("authorized_action")
    ):
        raise _AdjudicationError(
            "disproved",
            "PERMIT_TYPE_FACT_PROFILE_MISMATCH",
            "authorization facts do not match the signed fact profile and action",
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
    effective_universal_semantics = _compose_universal_semantics(
        universal_semantics,
        source=f"universal_verification_{universal_version}.json",
    )
    return _ResolvedContracts(
        selector_registry=selector_registry,
        selector_entry=selector_entry,
        fact_registry=fact_registry,
        fact_profile=fact_profile,
        facts_schema=facts_schema,
        universal_semantics=effective_universal_semantics,
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
            and receipt.get("state") not in {"rejected", "outcome_unknown"}
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


def _delegate_child_linkage_assessment(
    *,
    body: Mapping[str, Any],
    facts: Mapping[str, Any],
    binding: Mapping[str, Any],
    signed_artifact_verifier: SignedArtifactVerifier | None,
) -> ExactClaimAssessment:
    """Verify intended -> created -> granted -> acting child continuity."""

    if binding.get("semantic_id") != "keel.action.agent_delegate.v1":
        return _assessment(
            DELEGATE_CHILD_LINKAGE_CLAIM,
            "disproved",
            "DELEGATE_CHILD_LINKAGE_NOT_APPLICABLE",
            "Delegate child-linkage was declared for a non-Delegate Permit",
        )
    evidence_values = [
        value
        for value in body.get("scope_evidence", [])
        if isinstance(value, Mapping)
        and value.get("version") == "keel.delegate_child_linkage.v1"
    ]
    if not evidence_values:
        return _assessment(
            DELEGATE_CHILD_LINKAGE_CLAIM,
            "insufficient_evidence",
            "DELEGATE_CHILD_LINKAGE_EVIDENCE_MISSING",
            "signed Delegate child-linkage evidence is missing",
            evidence=("body.scope_evidence",),
        )
    if len(evidence_values) != 1:
        return _assessment(
            DELEGATE_CHILD_LINKAGE_CLAIM,
            "disproved",
            "DELEGATE_CHILD_LINKAGE_AMBIGUOUS",
            "the exact pack contains multiple Delegate child-linkage artifacts",
            evidence=("body.scope_evidence",),
        )
    evidence = evidence_values[0]
    signed, error = _signed_artifact_status(
        evidence,
        schema_name="delegate-child-linkage-v1.schema.json",
        purpose="delegate_child_linkage_signing",
        signed_at_field="asserted_at",
        verifier=signed_artifact_verifier,
    )
    if not signed:
        return _assessment(
            DELEGATE_CHILD_LINKAGE_CLAIM,
            "disproved" if error and "hash" in error else "unverifiable_scope",
            "DELEGATE_CHILD_LINKAGE_SIGNATURE_INVALID",
            error or "Delegate child-linkage signature is invalid",
            evidence=("body.scope_evidence",),
        )

    identity_pairs = (
        (evidence.get("permit_id"), body.get("permit_id")),
        (evidence.get("project_id"), body.get("project_id")),
        (evidence.get("semantic_id"), binding.get("semantic_id")),
        (
            evidence.get("authorization_request_digest"),
            facts.get("request_digest"),
        ),
    )
    if any(actual != expected for actual, expected in identity_pairs):
        return _assessment(
            DELEGATE_CHILD_LINKAGE_CLAIM,
            "disproved",
            "DELEGATE_CHILD_LINKAGE_IDENTITY_MISMATCH",
            "Delegate linkage Permit, project, semantic, or request identity diverges",
            evidence=("body.scope_evidence", "body.authorization_facts"),
        )
    intended = facts.get("intended_child_reference_commitment")
    if evidence.get("intended_child_reference_commitment") != intended:
        return _assessment(
            DELEGATE_CHILD_LINKAGE_CLAIM,
            "disproved",
            "DELEGATE_INTENDED_CHILD_MISMATCH",
            "linkage evidence does not carry the signed intended-child commitment",
            evidence=("body.scope_evidence", "body.authorization_facts"),
        )
    if evidence.get("created_child_reference_commitment") != intended:
        return _assessment(
            DELEGATE_CHILD_LINKAGE_CLAIM,
            "disproved",
            "DELEGATE_CREATED_CHILD_MISMATCH",
            "the created child does not match the child authorized by the Delegate Permit",
            evidence=("body.scope_evidence",),
        )
    authority_grant = evidence.get("authority_grant")
    granted_child = (
        authority_grant.get("delegate_child_reference_commitment")
        if isinstance(authority_grant, Mapping)
        else None
    )
    if granted_child != intended:
        return _assessment(
            DELEGATE_CHILD_LINKAGE_CLAIM,
            "disproved",
            "DELEGATE_GRANT_CHILD_MISMATCH",
            "the authority grant was issued to a different child commitment",
            evidence=("body.scope_evidence",),
        )
    created_at = _parse_time(evidence.get("created_at"))
    granted_at = _parse_time(
        authority_grant.get("issued_at")
        if isinstance(authority_grant, Mapping)
        else None
    )
    asserted_at = _parse_time(evidence.get("asserted_at"))
    if (
        created_at is None
        or granted_at is None
        or asserted_at is None
        or created_at > granted_at
        or granted_at > asserted_at
    ):
        return _assessment(
            DELEGATE_CHILD_LINKAGE_CLAIM,
            "disproved",
            "DELEGATE_CHILD_LINKAGE_TIME_INVALID",
            "Delegate child creation, grant, and assertion times are not causally ordered",
            evidence=("body.scope_evidence",),
        )
    acting = evidence.get("acting_child")
    if acting is None:
        return _assessment(
            DELEGATE_CHILD_LINKAGE_CLAIM,
            "insufficient_evidence",
            "DELEGATE_ACTING_CHILD_EVIDENCE_MISSING",
            "the child was created and granted authority, but no child dispatch is evidenced",
            evidence=("body.scope_evidence",),
        )
    if not isinstance(acting, Mapping) or acting.get(
        "child_reference_commitment"
    ) != intended:
        return _assessment(
            DELEGATE_CHILD_LINKAGE_CLAIM,
            "disproved",
            "DELEGATE_ACTING_CHILD_MISMATCH",
            "the child that acted does not match the authorized child commitment",
            evidence=("body.scope_evidence",),
        )
    dispatched_at = _parse_time(acting.get("dispatched_at"))
    if dispatched_at is None or dispatched_at < granted_at or dispatched_at > asserted_at:
        return _assessment(
            DELEGATE_CHILD_LINKAGE_CLAIM,
            "disproved",
            "DELEGATE_ACTING_CHILD_TIME_INVALID",
            "the evidenced child dispatch is outside the grant/assertion interval",
            evidence=("body.scope_evidence",),
        )
    return _assessment(
        DELEGATE_CHILD_LINKAGE_CLAIM,
        "supported",
        "DELEGATE_CHILD_LINKAGE_VERIFIED",
        "the authorized, created, granted, and acting child commitments match",
        evidence=("body.scope_evidence", "body.authorization_facts"),
    )


def _consequence_exact_assessment(
    *,
    claim_name: str,
    assessments: Mapping[str, ExactClaimAssessment],
    body: Mapping[str, Any],
    facts: Mapping[str, Any],
    binding: Mapping[str, Any],
    canonical_payload: Mapping[str, Any],
) -> ExactClaimAssessment:
    """Adjudicate the explicit Generate Text and Refund consequence claims."""

    if claim_name == GENERATE_TEXT_EXACT_REQUEST_CLAIM:
        expected_semantic = "keel.action.generate_text.v1"
        expected_profile = "keel.facts.generate_text_exact.v1"
        required = (
            "permit.type.v1",
            "permit.exact_target.v1",
            "permit.material_request.v1",
            "permit.enforced_at_certified_boundary.v1",
        )
        mismatch_reason = "GENERATE_TEXT_EXACT_REQUEST_MISMATCH"
        unproven_reason = "GENERATE_TEXT_CERTIFIED_BOUNDARY_UNPROVEN"
    elif claim_name == REFUND_ORIGINAL_PAYMENT_BOUND_CLAIM:
        expected_semantic = "keel.action.payment_refund.v1"
        expected_profile = "keel.facts.refund_exact.v1"
        required = (
            "permit.type.v1",
            "permit.exact_target.v1",
            "permit.material_request.v1",
        )
        mismatch_reason = "REFUND_ORIGINAL_PAYMENT_BINDING_MISMATCH"
        unproven_reason = "REFUND_AUTHORIZATION_BINDING_UNPROVEN"
    else:  # pragma: no cover - caller supplies the closed claim set
        raise ValueError(f"unsupported consequence claim: {claim_name}")

    if (
        binding.get("semantic_id") != expected_semantic
        or binding.get("fact_profile_id") != expected_profile
    ):
        return _assessment(
            claim_name,
            "disproved",
            mismatch_reason,
            "the consequence claim does not match the signed Permit semantic and fact profile",
            evidence=("body.semantic_binding", "body.authorization_facts"),
        )

    required_assessments = [assessments.get(name) for name in required]
    if any(item is None for item in required_assessments):
        return _assessment(
            claim_name,
            "unverifiable_scope",
            unproven_reason,
            "the verifier did not adjudicate every prerequisite claim",
        )
    resolved = [item for item in required_assessments if item is not None]
    if any(item.verdict == "disproved" for item in resolved):
        return _assessment(
            claim_name,
            "disproved",
            mismatch_reason,
            "a prerequisite exact authorization or enforcement claim was disproved",
            evidence=tuple(item.name for item in resolved),
        )
    if any(item.verdict == "unverifiable_scope" for item in resolved):
        return _assessment(
            claim_name,
            "unverifiable_scope",
            unproven_reason,
            "the prerequisite exact evidence scope is not independently verifiable",
            evidence=tuple(item.name for item in resolved),
        )
    if not all(item.verdict == "supported" for item in resolved):
        return _assessment(
            claim_name,
            "insufficient_evidence",
            unproven_reason,
            "the consequence claim lacks supported prerequisite evidence",
            evidence=tuple(item.name for item in resolved),
        )

    if claim_name == GENERATE_TEXT_EXACT_REQUEST_CLAIM:
        enforcement = body.get("enforcement_evidence")
        certification = (
            enforcement.get("adapter_certification")
            if isinstance(enforcement, Mapping)
            else None
        )
        if not isinstance(certification, Mapping):
            return _assessment(
                claim_name,
                "insufficient_evidence",
                unproven_reason,
                "the exact Generate Text Permit lacks certified-adapter evidence",
                evidence=("body.enforcement_evidence",),
            )
        facts_match = all(
            (
                facts.get("action") == "ai.generate",
                facts.get("operation") == "generate.text",
                facts.get("adapter_id") == certification.get("adapter_id"),
                facts.get("adapter_version")
                == certification.get("adapter_version"),
                facts.get("certification_id")
                == certification.get("certification_id"),
                binding.get("semantic_id")
                in certification.get("semantic_ids", []),
            )
        )
        if not facts_match:
            return _assessment(
                claim_name,
                "disproved",
                "GENERATE_TEXT_ADAPTER_BINDING_MISMATCH",
                "signed Generate Text facts diverge from certified-adapter evidence",
                evidence=("body.authorization_facts", "body.enforcement_evidence"),
            )
        return _assessment(
            claim_name,
            "supported",
            "GENERATE_TEXT_EXACT_REQUEST_VERIFIED",
            "the signed Generate Text request and certified adapter identities match",
            evidence=("body.authorization_facts", "body.enforcement_evidence"),
        )

    signed_expiry = _parse_time(canonical_payload.get("expires_at"))
    facts_expiry = _parse_time(facts.get("expires_at"))
    if not all(
        (
            facts.get("action") == "payment.refund",
            facts.get("max_uses") == 1,
            _signed_maximum_uses(canonical_payload) == 1,
            signed_expiry is not None,
            signed_expiry == facts_expiry,
        )
    ):
        return _assessment(
            claim_name,
            "disproved",
            "REFUND_SIGNED_LIMITS_MISMATCH",
            "Refund facts, one-use limit, or expiry diverge from the signed Permit",
            evidence=("body.authorization_facts", "body.permit_decision"),
        )
    return _assessment(
        claim_name,
        "supported",
        "REFUND_ORIGINAL_PAYMENT_BOUND",
        "the signed Refund Permit binds the exact original-payment relationship and limits",
        evidence=("body.authorization_facts", "body.permit_decision"),
    )


def _runtime_proof_schema_name(runtime_proof: Mapping[str, Any]) -> str | None:
    return {
        "keel.runtime_enforcement_proof.v1": (
            "runtime-enforcement-proof-v1.schema.json"
        ),
        "keel.runtime_enforcement_proof.v2": (
            "runtime-enforcement-proof-v2.schema.json"
        ),
    }.get(str(runtime_proof.get("version") or ""))


def _enforcement_regime_assessments(
    *,
    body: Mapping[str, Any],
    signed_attributes: Mapping[str, Any],
    permit_id: str,
    project_id: str,
    semantic_id: str,
    material_values: list[Any],
    signed_artifact_verifier: SignedArtifactVerifier | None,
) -> dict[str, ExactClaimAssessment]:
    assessments: dict[str, ExactClaimAssessment] = {}
    issuance_state = signed_attributes.get("permit_enforcement_state_v1")
    if not isinstance(issuance_state, Mapping):
        assessments[ENFORCEMENT_REGIME_AT_ISSUANCE_CLAIM] = _assessment(
            ENFORCEMENT_REGIME_AT_ISSUANCE_CLAIM,
            "insufficient_evidence",
            "ENFORCEMENT_REGIME_AT_ISSUANCE_NOT_RECORDED",
            "the historical signed Permit does not record its issuance-time Work regime",
            evidence=("body.permit_decision.resource_attributes_json",),
        )
    else:
        try:
            _validate_schema(
                issuance_state,
                "permit-enforcement-state-v1.schema.json",
            )
        except jsonschema.ValidationError as exc:
            assessments[ENFORCEMENT_REGIME_AT_ISSUANCE_CLAIM] = _assessment(
                ENFORCEMENT_REGIME_AT_ISSUANCE_CLAIM,
                "disproved",
                "ENFORCEMENT_ISSUANCE_STATE_INVALID",
                f"the signed issuance regime is invalid: {exc.message}",
                evidence=("body.permit_decision.resource_attributes_json",),
            )
        else:
            assessments[ENFORCEMENT_REGIME_AT_ISSUANCE_CLAIM] = _assessment(
                ENFORCEMENT_REGIME_AT_ISSUANCE_CLAIM,
                "supported",
                "ENFORCEMENT_REGIME_AT_ISSUANCE_VERIFIED",
                "the signed Permit records a schema-valid Work regime at issuance",
                evidence=("body.permit_decision.resource_attributes_json",),
            )

    enforcement = body.get("enforcement_evidence")
    runtime_proof = (
        enforcement.get("runtime_enforcement_proof")
        if isinstance(enforcement, Mapping)
        else None
    )
    if not isinstance(runtime_proof, Mapping) or runtime_proof.get(
        "version"
    ) == "keel.runtime_enforcement_proof.v1":
        assessments[ENFORCEMENT_REGIME_AT_DISPATCH_CLAIM] = _assessment(
            ENFORCEMENT_REGIME_AT_DISPATCH_CLAIM,
            "insufficient_evidence",
            "ENFORCEMENT_REGIME_AT_DISPATCH_NOT_RECORDED",
            "the dispatch proof is absent or predates enforcement-regime recording",
            evidence=("body.enforcement_evidence",),
        )
        return assessments

    schema_name = _runtime_proof_schema_name(runtime_proof)
    if schema_name != "runtime-enforcement-proof-v2.schema.json":
        assessments[ENFORCEMENT_REGIME_AT_DISPATCH_CLAIM] = _assessment(
            ENFORCEMENT_REGIME_AT_DISPATCH_CLAIM,
            "unverifiable_scope",
            "ENFORCEMENT_PROOF_VERSION_UNSUPPORTED",
            "the runtime proof version is not supported for regime adjudication",
            evidence=("body.enforcement_evidence.runtime_enforcement_proof",),
        )
        return assessments
    signed, signed_error = _signed_artifact_status(
        runtime_proof,
        schema_name=schema_name,
        purpose="runtime_enforcement_signing",
        signed_at_field="evaluated_at",
        verifier=signed_artifact_verifier,
    )
    if not signed:
        assessments[ENFORCEMENT_REGIME_AT_DISPATCH_CLAIM] = _assessment(
            ENFORCEMENT_REGIME_AT_DISPATCH_CLAIM,
            "disproved" if signed_artifact_verifier is not None else "insufficient_evidence",
            "ENFORCEMENT_DISPATCH_PROOF_INVALID",
            signed_error or "the runtime proof signature is invalid",
            evidence=("body.enforcement_evidence.runtime_enforcement_proof",),
        )
        return assessments
    identity_matches = all(
        (
            runtime_proof.get("permit_id") == permit_id,
            runtime_proof.get("project_id") == project_id,
            runtime_proof.get("semantic_id") == semantic_id,
            runtime_proof.get("exact_request_digest") in material_values,
            runtime_proof.get("enforcement_surface_key") == "program:work",
        )
    )
    assessments[ENFORCEMENT_REGIME_AT_DISPATCH_CLAIM] = _assessment(
        ENFORCEMENT_REGIME_AT_DISPATCH_CLAIM,
        "supported" if identity_matches else "disproved",
        (
            "ENFORCEMENT_REGIME_AT_DISPATCH_VERIFIED"
            if identity_matches
            else "ENFORCEMENT_DISPATCH_IDENTITY_MISMATCH"
        ),
        (
            "the signed pre-effect proof records the Work regime for this exact dispatch"
            if identity_matches
            else "the runtime proof does not bind this Permit, project, semantic, request, or Work surface"
        ),
        evidence=("body.enforcement_evidence.runtime_enforcement_proof",),
    )
    return assessments


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
    """Adjudicate every declared v2/v3 claim without silently dropping failures."""

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
            verifier_safe_facts={},
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

    semantic_id = str(binding.get("semantic_id") or "")
    conditional_claims = contracts.universal_semantics.get("body", {}).get(
        "conditional_claims", {}
    )
    expected_conditional = (
        conditional_claims.get(semantic_id, [])
        if isinstance(conditional_claims, Mapping)
        else []
    )
    missing_conditional = [
        str(name)
        for name in expected_conditional
        if isinstance(name, str) and name not in declared
    ]
    if missing_conditional:
        declared.extend(missing_conditional)
        return fail_all(
            _AdjudicationError(
                "disproved",
                "PERMIT_CONDITIONAL_CLAIM_MISSING",
                "the exact pack omitted a consequence claim required by its pinned recipe",
            )
        )

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
        _verify_trusted_preflight_window(
            facts=facts,
            canonical_payload=canonical_payload,
        )
        _verify_transactional_cx_invariants(facts)
        _verify_release_invariants(facts)
        _verify_identity_security_invariants(facts)
        _verify_coding_workspace_invariants(facts)
    except _AdjudicationError as exc:
        return fail_all(exc)
    work_enforcement_state = decision_attrs.get("permit_enforcement_state_v1")
    work_governed = bool(
        (
            isinstance(work_enforcement_state, Mapping)
            and work_enforcement_state.get("enforcement_surface_key")
            == "program:work"
        )
        or isinstance(decision_attrs.get("work_binding_v1"), Mapping)
        or isinstance(decision_attrs.get("work_package_v1"), Mapping)
    )
    evidence_claims = contracts.universal_semantics.get("body", {}).get(
        "conditional_evidence_claims", {}
    )
    if work_governed and isinstance(evidence_claims, Mapping):
        work_recipe = evidence_claims.get("program:work")
        if isinstance(work_recipe, Mapping):
            expected_work_claims = [
                str(name)
                for phase in ("issuance", "dispatch")
                for name in work_recipe.get(phase, [])
                if isinstance(name, str)
            ]
            missing_work_claims = [
                name for name in expected_work_claims if name not in declared
            ]
            if missing_work_claims:
                declared.extend(missing_work_claims)
                return fail_all(
                    _AdjudicationError(
                        "disproved",
                        "PERMIT_CONDITIONAL_CLAIM_MISSING",
                        "the exact pack omitted Work enforcement claims required by its pinned recipe",
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

    if work_governed and any(
        name in declared for name in ENFORCEMENT_REGIME_CLAIMS
    ):
        assessments.update(
            _enforcement_regime_assessments(
                body=body,
                signed_attributes=decision_attrs,
                permit_id=permit_id,
                project_id=project_id,
                semantic_id=semantic_id,
                material_values=material_values,
                signed_artifact_verifier=signed_artifact_verifier,
            )
        )

    dispatch_at: datetime | None = None
    runtime_signature_ok = False
    if isinstance(runtime_proof, Mapping):
        runtime_schema_name = _runtime_proof_schema_name(runtime_proof)
        if runtime_schema_name is not None:
            runtime_signature_ok, _ = _signed_artifact_status(
                runtime_proof,
                schema_name=runtime_schema_name,
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
            runtime_schema_name = _runtime_proof_schema_name(runtime_proof)
            if runtime_schema_name is None:
                runtime_ok, runtime_error = (
                    False,
                    "runtime enforcement proof version is unsupported",
                )
            else:
                runtime_ok, runtime_error = _signed_artifact_status(
                    runtime_proof,
                    schema_name=runtime_schema_name,
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
    if DELEGATE_CHILD_LINKAGE_CLAIM in declared:
        assessments[DELEGATE_CHILD_LINKAGE_CLAIM] = (
            _delegate_child_linkage_assessment(
                body=body,
                facts=facts,
                binding=binding,
                signed_artifact_verifier=signed_artifact_verifier,
            )
        )
    for claim_name in (
        GENERATE_TEXT_EXACT_REQUEST_CLAIM,
        REFUND_ORIGINAL_PAYMENT_BOUND_CLAIM,
    ):
        if claim_name not in declared:
            continue
        assessments[claim_name] = _consequence_exact_assessment(
            claim_name=claim_name,
            assessments=assessments,
            body=body,
            facts=facts,
            binding=binding,
            canonical_payload=canonical_payload,
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
        verifier_safe_facts=_verifier_safe_facts(contracts.fact_profile, facts),
        claims=tuple(assessments[name] for name in declared if name in assessments),
    )


__all__ = [
    "DELEGATE_CHILD_LINKAGE_CLAIM",
    "ENFORCEMENT_REGIME_AT_DISPATCH_CLAIM",
    "ENFORCEMENT_REGIME_AT_ISSUANCE_CLAIM",
    "ENFORCEMENT_REGIME_CLAIMS",
    "GENERATE_TEXT_EXACT_REQUEST_CLAIM",
    "PROFILE",
    "PROFILE_VERSION",
    "PROFILE_V3",
    "PROFILE_V3_VERSION",
    "REFUND_ORIGINAL_PAYMENT_BOUND_CLAIM",
    "SUPPORTED_PROFILES",
    "UNIVERSAL_CLAIMS",
    "ExactClaimAssessment",
    "PermitExactV2Result",
    "adjudicate_permit_exact_v2_body",
]
